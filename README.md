# Inhibitor

Inhibitor is an asynchronous, zero-latency, AI-powered Web Application Firewall (WAF) and API Gateway. Built specifically for high-throughput environments, it ensures that your core applications are never bottlenecked by security analysis.

## Architecture Concept: Asynchronous Shadow Mode

Traditional WAFs analyze incoming traffic synchronously, adding latency to every request. Inhibitor takes a different approach:
- **Zero-Latency Pass-Through:** Every request is instantly checked against an O(1) Redis in-memory blacklist. If the IP is safe, the request immediately passes through.
- **Asynchronous AI Inspection:** A copy of the traffic (Headers, Query Params, Body) is sent to a Redis Queue (RQ) in the background.
- **LLM Threat Analysis:** An autonomous AI worker analyzes the traffic against OWASP Top 10 vulnerabilities (SQLi, XSS, RCE, SSRF, etc.).
- **Auto-Ban:** If the AI detects a threat, the offending IP is instantly added to the Redis blacklist for 24 hours. Subsequent requests from that IP are blocked at the gateway level in milliseconds.

## Features

- **Fail-Open Design:** Zero downtime. If Redis or the AI API goes down, the gateway continues to serve traffic seamlessly.
- **Cloud-Agnostic & Dockerized:** Ready to be deployed on AWS ECS, Kubernetes, or any Docker-compatible environment.
- **LLM Powered:** Uses large language models (OpenAI, Groq, etc.) to understand the context of the attack, not just regex rules.

## Tech Stack

- **Gateway:** Python, FastAPI, Uvicorn
- **Cache & Message Queue:** Redis, RQ (Redis Queue)
- **AI Engine:** OpenAI / Groq (Compatible API Structure)
- **Orchestration:** Docker Compose

## Quick Start

1. Set up your `.env` file in the root directory:
```env
LLM_API_KEY=your_api_key_here
LLM_API_BASE=https://api.openai.com/v1
LLM_MODEL=gpt-4o
```

2. Build and start the services:
```bash
docker compose up --build -d
```

3. Test the Gateway:
```bash
# Benign Request (Passes through)
curl http://localhost:8000/api/test

# Malicious Request (Passes through initially, gets banned in milliseconds)
curl "http://localhost:8000/login?user=admin'--&pass=123"

# Subsequent Requests from the same IP
# Response: 403 Forbidden
```

## Integrating into Existing Projects (e.g. Nexus)

Inhibitor is designed to be placed in front of your core services. By updating the FastAPI routing, you can easily proxy valid traffic directly to your internal services (Nexus) while Inhibitor handles the asynchronous shadow security.

## License
MIT
