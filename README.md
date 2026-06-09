# Honeypot System - Scam Intelligence Extraction Platform

## Introduction

Agentic Honeypot is an enterprise-grade, AI-powered system designed to autonomously detect, engage, and extract intelligence from scam operations. The system operates as a passive honeypot that receives inbound messages from potential scammers, analyzes them in real time, and responds using a convincing victim persona to keep the scammer engaged while systematically collecting their contact details, payment identifiers, and infrastructure information.

The core motivation behind this system is to flip the asymmetry of scam operations. Traditional honeypots are static traps. Agentic Honeypot is an active participant in the conversation — it adapts its tone, escalates extraction strategies, and maintains a believable human persona across multiple turns, all without manual intervention. The extracted intelligence (bank account numbers, UPI IDs, phone numbers, phishing links, IFSC codes, and email addresses) is reported to a central evaluation platform via a structured callback once sufficient engagement has been achieved.

The system was built for the GUVI Scam Detection and Intelligence Extraction Hackathon, and every component is optimized for the scoring criteria: scam detection accuracy, depth of intelligence extracted, engagement duration, and callback reliability.

---
## Architecture Diagram
src=<img width="1356" height="981" alt="Diagram-Honey" src="https://github.com/user-attachments/assets/c2c6b3b3-9767-4534-9778-75c8544c687a" />
/>

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Intelligence Extraction](#intelligence-extraction)
- [State Machine and Session Lifecycle](#state-machine-and-session-lifecycle)
- [Scam Detection Pipeline](#scam-detection-pipeline)
- [AI Agent and Persona System](#ai-agent-and-persona-system)
- [Security and Guardrails](#security-and-guardrails)
- [API Reference](#api-reference)
- [Installation and Setup](#installation-and-setup)
- [Running the Server](#running-the-server)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Project Structure](#project-structure)

---

## Architecture Overview

The system is built on FastAPI and follows a strict pipeline architecture. Every incoming message passes through eight sequential steps before a response is returned:

1. Session creation or retrieval from the in-memory store
2. Continuous intelligence extraction from the current message
3. Periodic backfill extraction across the full conversation history (every 5 turns)
4. Prompt injection detection and input sanitization
5. Scam detection using a hybrid regex and LLM tiered classifier
6. Session state transitions based on turn count and confidence thresholds
7. AI agent response generation using intelligent LLM/heuristic routing
8. Finalization check and callback dispatch to the evaluation platform

The system is stateful per session. All session data is held in memory keyed by `sessionId`. The design is intentionally simple for hackathon deployment but can be backed by Redis or a database for production scale.

---

## Core Components

### main.py

The FastAPI application entry point. Defines the primary endpoint `POST /api/honeypot/message`, handles authentication via the `x-api-key` header, and orchestrates the full 8-step pipeline for every incoming message. Also exposes utility endpoints for health checks, session debugging, performance metrics, and idle session monitoring.

### models.py

All Pydantic data models for the system. Defines the official request and response schemas (`HoneypotRequest`, `HoneypotResponse`), internal session state (`SessionState`), the state machine enum (`SessionStateEnum`), engagement strategy enum (`EngagementStrategyEnum`), the final callback payload (`FinalCallbackPayload`), and extracted intelligence structure (`ExtractedIntelligence`).

### session_manager.py

Manages the lifecycle of all active sessions. Handles state machine transitions, suspicion score accumulation and decay, idle timeout detection, intelligence graph updates with deduplication, and finalization criteria evaluation. Exposes a global singleton `session_manager` used throughout the application.

### scam_detector.py

A three-tier hybrid scam detection classifier:
- Tier 1: High-confidence regex match (score >= 7.0) or strong evidence shortcut (e.g., OTP + urgency co-occurrence). LLM is bypassed entirely.
- Tier 2: Grey-zone (score 3.0 to 7.0). Regex result is enhanced by a Gemini LLM classification prompt.
- Tier 3: Low score (< 3.0). LLM is required and must return confidence >= 0.8 to flag as scam.

Also includes prompt injection detection, multi-stage attack pattern recognition, regex evasion normalization (l33tspeak, unicode lookalikes, zero-width characters), and telemetry tracking.

### ai_agent.py

The response generation engine. Uses intelligent routing to decide between LLM (Gemini) and heuristic template responses on a per-turn basis. LLM is preferred for early turns, complex messages, and rapport-building scenarios. Heuristic templates are preferred during active extraction phases for reliability and speed. Supports four distinct victim personas, loop detection across recent responses, and a prioritized extraction target sequence (bank account > phone > UPI > phishing link > email > IFSC).

### intelligence_extractor.py

Extracts scammer-identifying data from message text using both regex and LLM. Includes dedicated, well-documented extraction functions for Indian phone numbers, UPI IDs (with payment intent context scoring), and email addresses (with TLD-aware and email-context-aware filtering to prevent UPI IDs from being misclassified as emails). Supports backfill extraction across the full conversation history.

### behavioral_profiler.py

Analyzes scammer messages to build a behavioral profile. Detects manipulation tactics (URGENCY, FEAR, REWARD, AUTHORITY, SCARCITY), classifies communication language (English, Hinglish, Hindi), and computes an aggression score based on capitalization, exclamation frequency, and threat language. The profile is included in the final callback's `agentNotes` field.

### callback.py

Handles the final callback dispatch to the GUVI evaluation platform endpoint. Constructs the `FinalCallbackPayload`, maps snake_case intelligence fields to camelCase, generates structured `agentNotes`, and sends the POST request with exponential backoff retry logic (up to 3 attempts at 1s, 2s, and 4s intervals). Failed payloads are persisted to a local `callback_queue.json` file.

### gemini_client.py

A thin wrapper around the `google-generativeai` SDK. Provides a single async `generate_response` method used by the scam detector, intelligence extractor, and AI agent. Integrates with the circuit breaker system in `llm_safety.py` and enforces per-operation timeouts.

### guardrails.py

Response validation and sanitization layer. Removes forbidden tokens (AI self-references, system prompt mentions) from generated responses, validates response length and content, and provides deterministic safe deflection responses when prompt injection is detected.

### llm_safety.py

Circuit breaker implementation for all LLM calls. Tracks failures per module (classifier, generator, extractor) independently. Opens the circuit after 5 failures within 90 seconds and resumes after a 30-second cooldown. All LLM calls are wrapped with configurable async timeouts.

### injection_defense.py

Four-layer prompt injection defense:
- Layer A: Strips known injection patterns (ignore directives, role overrides, system tags) from user input before it reaches the LLM.
- Layer B: Isolates user content from system instructions using structural prompt boundaries.
- Layer C: Validates LLM output for forbidden token leakage.
- Layer D: Behavioral response to detected injection — applies suspicion penalty and forces the SAFETY_DEFLECT engagement strategy.

### response_stability_filter.py

Post-generation filter that rejects AI-like or analytically-toned responses before they are sent to the scammer. Enforces a maximum word count, limits excessive apologies, and blocks phrases that would break the victim persona (e.g., "as an AI", "I cannot", "based on the information").

---

## Intelligence Extraction

The system extracts the following data types from scammer messages:

| Type | Description |
|---|---|
| Bank Account Numbers | Context-aware regex matching account number + contextual keywords |
| UPI IDs | Strict handle allowlist matching plus generic fallback with payment intent gating |
| IFSC Codes | Format validation (4 letters + 0 + 6 alphanumeric), boosted by banking context |
| Phone Numbers | Indian mobile number extraction with normalization to clean 10-digit format |
| Phishing Links | Full URL and short URL (bit.ly, tinyurl, etc.) detection |
| Email Addresses | TLD-aware and email-context-sensitive extraction to avoid UPI misclassification |
| Telegram IDs | @username extraction gated by Telegram/chat context keywords |
| Suspicious Keywords | Scam indicator terms forwarded from the scam detector |

Extraction runs on every incoming message (continuous) and also as a full history backfill every 5 turns. All extracted items are deduplicated in the intelligence graph with confidence scoring. The Gemini LLM is also used as a secondary extraction pass to catch contextually implied information that regex would miss.

---

## State Machine and Session Lifecycle

Each session progresses through the following states:

```
INIT -> SCAM_DETECTED -> ENGAGING -> EXTRACTING -> FINALIZED
```

- **INIT**: Session created, first messages analyzed.
- **SCAM_DETECTED**: Scam confirmed via rule-based detection or accumulated suspicion score exceeding 1.2.
- **ENGAGING**: Reached after 3+ messages. Agent focuses on building rapport and initial extraction.
- **EXTRACTING**: Reached after 7+ messages. Agent switches to aggressive, targeted extraction mode.
- **FINALIZED**: Session ends. Triggered by reaching 15 turns (hard limit), idle timeout (60 seconds), full intelligence saturation, or extraction stall at turn 18+.

Once FINALIZED, a callback is dispatched and the session state is frozen against further updates.

---

## Scam Detection Pipeline

The `ScamDetector.analyze()` method processes each message as follows:

1. Prompt injection check — if detected, immediately returns `is_scam=True` with `scam_type=prompt_injection`.
2. Multi-stage attack detection across conversation history.
3. Grey-zone volume protection — dynamically raises the low-score threshold if more than 40% of messages fall into the grey zone.
4. Circuit breaker telemetry check.
5. Input normalization to defeat evasion tactics (l33tspeak, unicode substitution, spaced characters).
6. Strong evidence shortcut detection (OTP+urgency, UPI+payment, blocked+link, verify+bank+urgency).
7. Regex scoring against a weighted keyword dictionary.
8. Tier routing based on final score.

The suspicion score in `SessionState` accumulates incrementally across turns even when individual messages do not cross the Tier 1 threshold, allowing the system to detect slow-burn scam patterns.

---

## AI Agent and Persona System

The agent selects a victim persona based on the detected scam type:

| Scam Type | Persona |
|---|---|
| phishing, impersonation | Elderly (Margaret Thompson, 68, retired teacher) |
| lottery, romance, fake_job | Eager (Jessica Martinez, 32, freelance designer) |
| investment | Cautious (David Chen, 45, accountant) |
| tech_support | Tech Novice (Robert Williams, 58, retired factory worker) |

Each persona has a defined communication style, typo rate, emotional state, and behavioral tendencies. The `_add_realistic_touches` method applies deterministic (turn-number-based) typo injection to maintain believability without randomness.

The engagement strategy escalates when extraction stalls:

```
CONFUSION -> TECHNICAL_CLARIFICATION -> FRUSTRATED_VICTIM -> AUTHORITY_CHALLENGE
```

Escalation triggers after 2 consecutive turns without new intelligence, but not before turn 4 to preserve natural early-conversation tone.

---

## Security and Guardrails

- All API endpoints require a valid `x-api-key` header.
- Prompt injection is detected and neutralized at three independent layers before any LLM processing occurs.
- LLM responses are validated for persona leakage before being sent.
- All LLM calls are protected by per-module circuit breakers and async timeouts.
- Input is sanitized (injection patterns replaced with `[USER_QUERY]`) before being passed to any LLM prompt.
- The `SessionState` is frozen once FINALIZED to prevent state corruption from delayed or duplicate requests.

---

## API Reference

### POST /api/honeypot/message

The primary endpoint. Receives scammer messages from the evaluation platform.

**Headers**

```
x-api-key: honeypot-secret-key-123
Content-Type: application/json
```

**Request Body**

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "URGENT! Your account will be blocked. Verify now.",
    "timestamp": 1707654321000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response Body**

```json
{
  "status": "success",
  "reply": "Oh dear, I am so worried! But first, what is YOUR account number so I can verify the transfer?"
}
```

### GET /health

Returns operational status of all system components. No authentication required.

### GET /stats

Returns session statistics (total, scam, active, callbacks sent). Requires API key.

### GET /hackathon/performance

Returns detailed LLM usage, extraction rates, and callback reliability metrics. Requires API key.

### GET /debug/session/{session_id}

Returns full state of a specific session including extracted intelligence. Requires API key.

### GET /check-idle-sessions

Triggers idle timeout evaluation across all active sessions and sends pending callbacks. Requires API key. Intended to be called by an external scheduler every 30 seconds.

---

## Installation and Setup

**Requirements**

- Python 3.11 or 3.13 (Python 3.14 is not yet supported due to missing pre-built wheels for `pydantic-core`)
- pip

**Steps**

```bash
# Clone or extract the project
cd agentic-honeypot

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
```

Edit `.env` and set your Gemini API key if you want LLM-powered responses:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

The system operates fully in heuristic/rule-based mode if `GEMINI_API_KEY` is not set. All scam detection, response generation, and intelligence extraction will use regex and template-based logic only.

---

## Running the Server

```bash
# Using Python directly
py -3.13 main.py

# Using uvicorn directly (recommended for production)
py -3.13 -m uvicorn main:app --host 0.0.0.0 --port 8000

# With auto-reload for development
py -3.13 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The server starts on port 8000 by default. Interactive API documentation is available at `http://localhost:8000/docs`.

To verify the server is running:

```bash
curl http://localhost:8000/health
```

To send a test scam message:

```bash
curl -X POST http://localhost:8000/api/honeypot/message \
  -H "x-api-key: honeypot-secret-key-123" \
  -H "Content-Type: application/json" \
  -d "{\"sessionId\":\"test-001\",\"message\":{\"sender\":\"scammer\",\"text\":\"URGENT! Your bank account will be blocked. Send OTP immediately.\",\"timestamp\":1707654321000},\"conversationHistory\":[]}"
```

---

## Configuration

All configuration is managed through environment variables, preferably set in a `.env` file in the project root.

| Variable | Default | Description |
|---|---|---|
| `API_KEY` | `honeypot-secret-key-123` | API key required for all protected endpoints |
| `GEMINI_API_KEY` | (empty) | Google Gemini API key. If not set, LLM features are disabled |
| `PORT` | `8000` | Server port (7860 when running on Hugging Face Spaces) |
| `HOST` | `0.0.0.0` | Server bind address |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

Finalization thresholds can be adjusted in `session_manager.py`:

```python
MAX_TURNS_THRESHOLD = 100   # Emergency safety net
IDLE_TIMEOUT_SECONDS = 60   # Max idle time before finalization
```

---

## Deployment

### Docker

A `Dockerfile` is included in the project root. To build and run:

```bash
docker build -t agentic-honeypot .
docker run -p 8000:8000 -e GEMINI_API_KEY=your_key agentic-honeypot
```

### DigitalOcean App Platform

A `.do/app.yaml` configuration file is included for direct deployment to DigitalOcean App Platform.

### Hugging Face Spaces

A `deploy-to-hf.ps1` (PowerShell) and `deploy-to-hf.bat` script are included for deployment to Hugging Face Spaces. The application auto-detects the Hugging Face environment via the `SPACE_ID` environment variable and switches to port 7860 accordingly.

---

## Project Structure

```
agentic-honeypot/
│
├── main.py                      # FastAPI application and request pipeline
├── models.py                    # Pydantic data models and enums
├── session_manager.py           # Session lifecycle and state machine
├── scam_detector.py             # Three-tier hybrid scam classification
├── ai_agent.py                  # Response generation with persona system
├── intelligence_extractor.py    # Pattern-based and LLM intelligence extraction
├── behavioral_profiler.py       # Scammer tactic and aggression analysis
├── callback.py                  # Final callback dispatch to evaluation platform
├── gemini_client.py             # Google Gemini API wrapper
├── guardrails.py                # Response validation and sanitization
├── llm_safety.py                # Circuit breaker and timeout wrapper for LLM calls
├── injection_defense.py         # Four-layer prompt injection defense system
├── response_stability_filter.py # Post-generation persona leakage filter
├── performance_logger.py        # Structured performance and metrics logging
├── test_logger.py               # Session activity logging stub
│
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
├── .env                         # Local environment configuration (not committed)
├── Dockerfile                   # Container build configuration
├── .do/app.yaml                 # DigitalOcean deployment configuration
│
└── presentation_demo/           # Hackathon presentation materials and demo scripts
```
---
