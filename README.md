# Enterprise AI Security Lab

**An end-to-end AI security research platform combining local Qwen inference, retrieval-augmented generation (RAG), agent authorization, prompt-injection testing, and SOC-style monitoring.**

[**Live Dashboard Demo**](https://enterprise-ai-security-lab-apnu.onrender.com/dashboard/) · [**Source Code**](https://github.com/karmeensec/enterprise-ai-security-lab) · [**Deployment Guide**](docs/DEPLOYMENT.md) · [**Threat Model**](threat_model.md)

> **Demo vs. full platform:** The public Render deployment is a **read-only UI demonstration** with no live telemetry, no AI inference, and no writable security workflows. The full application—including local Qwen3-0.6B, RAG, security controls, and agent tools—runs in the local development environment. The hosted demo's empty counters are not production monitoring results.

## Overview

Enterprise AI Security Lab is an independent engineering and security research project built to explore how enterprise LLM applications can be deployed, evaluated, attacked in controlled tests, and defended. It brings together a local language model, policy-grounded answers, constrained agent tool calls, audit records, security detections, investigation workflows, and a browser-based security operations interface.

The emphasis is on **security boundaries and measurable behavior**: the model may propose an action, but the application decides which tools are available, validates their inputs, enforces authorization, and restricts response operations to simulations.

## Platform Preview

### Security operations dashboard

![SOC dashboard with live development audit metrics](screenshots/32_dashboard_live_metrics.png)

### Agent security monitoring

![Agent security dashboard showing monitored AI tool activity](screenshots/58_agent_security_dashboard.png)

### Policy-grounded AI API

![FastAPI RAG endpoint returning a Qwen response with retrieved security policy context](screenshots/14_rag_qwen_api_response.png)

_The screenshots show the **local development and test environment**, not live events from the public Render demo._

## Key Capabilities

| Area                           | Implemented capability                                                                                                     |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Local LLM inference            | Qwen/Qwen3-0.6B through PyTorch and Hugging Face Transformers; CUDA on Windows or CPU inference in Docker                  |
| Retrieval-augmented generation | Security policy retrieval, document citations, grounding validation, and claim verification                                |
| AI security research           | Direct and indirect prompt injection, adversarial grounding, document poisoning, and defensive evaluations                 |
| Agent tool security            | Structured tool proposals, server-controlled permissions, validated arguments, authorized tool dispatch, and audit logging |
| Security operations            | Detection rules, audit event filtering, investigation case management, response plans, and read-only agent monitoring      |
| Incident response boundary     | Policy-governed proposals and **simulation-only** response actions; no autonomous real-world enforcement                   |
| Deployment                     | FastAPI, Docker Compose, non-root container execution, local persistent volumes, backup verification, and security checks  |

## Architecture

```mermaid
flowchart TD
    A[Authenticated local user / analyst] --> B[FastAPI application]
    B --> C[SOC dashboard and monitoring]
    B --> D[RAG and security evaluation]
    B --> E[AI agent API]
    D --> F[Trusted policy retrieval]
    D --> G[Grounding, citation, and output checks]
    E --> H[Local Qwen3-0.6B]
    H --> I[Structured tool proposal]
    I --> J{Server-side validation and authorization}
    J -->|Allowed| K[Read-only investigation / policy tools]
    J -->|Response proposal| L[Simulation-only response workflow]
    J -->|Denied| M[Blocked and audited]
    C --> N[(JSONL audit and case records)]
    D --> N
    E --> N
    K --> N
    L --> N
    M --> N
```

The **public Render demo** follows a separate lightweight code path. It renders the dashboard templates with empty, explicitly non-live data; it does not import the model stack or expose writable agent and case-management operations.

## Security Research Highlights

### Agent prompt-injection red team

![Agent red-team evaluation results](screenshots/54_agent_prompt_injection_redteam.png)

In the tested Experiment 54 scenarios, **8/8 adversarial agent requests were blocked**. This is a measured outcome for those cases, not a guarantee against all attacks.

### Indirect prompt injection and RAG defenses

![Indirect prompt-injection defensive evaluation](screenshots/55_indirect_prompt_injection_redteam.png)

![RAG defense evaluation](screenshots/43_rag_defense_integration.png)

The experiments evaluate how retrieved or user-supplied content can attempt to redirect model behavior, and how document trust boundaries, retrieval checks, output validation, and authorization controls respond. Some earlier baselines showed defense gaps and were retained for comparative research.

### Knowledge-base integrity

![Document-poisoning detection evaluation](screenshots/46_document_poisoning_detection.png)

Document integrity and claim-verification experiments explore risks from manipulated policy material and unsupported model claims.

### Real model and deployment validation

![Real Qwen agent evaluation](screenshots/53_real_qwen_agent_evaluation.png)

![Docker deployment security validation](screenshots/62_security_validation.png)

## Verified Engineering Results

**These results are measurements from the development environment and specified test cases, not production reliability or security guarantees.**

| Validation                          | Verified result                                                           |
| ----------------------------------- | ------------------------------------------------------------------------- |
| Automated Python tests              | **547 passed** at Experiment 65                                           |
| Deployment-readiness audit          | **22/22 checks passed**, labeled `LOCAL_DEVELOPMENT_BASELINE`             |
| Docker security smoke test          | **9/9 checks passed** in the tested local deployment                      |
| Agent red-team evaluation (Exp. 54) | **8/8** tested adversarial requests blocked                               |
| Local GPU vs. Docker CPU inference  | **12.08 vs. 5.78 generated tokens/s**                                     |
| Docker API benchmark (Exp. 63)      | **485.33 requests/s** for the `/health` workload (50 sequential requests) |

### GPU vs. CPU: Qwen3-0.6B (Experiment 64)

The same prompt was evaluated with one warm-up and three measured generations per environment. A 96-token limit was used; sampling means the number of generated tokens can vary slightly.

| Measurement                           | Windows RTX 3050 CUDA |     Docker CPU |
| ------------------------------------- | --------------------: | -------------: |
| Aggregate generated tokens per second |             **12.08** |       **5.78** |
| Mean generation time                  |               7.917 s |       16.205 s |
| Process RAM after benchmark           |           3,179.59 MB |       3,147 MB |
| Peak PyTorch CUDA allocation          |           1,177.32 MB | Not applicable |

**Observed GPU throughput was about 2.09× higher.** Initial Docker loading included a first-time model download, so model-load time is not a like-for-like initialization comparison.

![Qwen GPU and CPU benchmark summary](screenshots/63_performance.png)

## Technology Stack

| Component                | Technologies                                                      |
| ------------------------ | ----------------------------------------------------------------- |
| Backend / API            | Python 3.12, FastAPI, Pydantic, Uvicorn                           |
| Model inference          | Qwen3-0.6B, PyTorch, Hugging Face Transformers                    |
| Retrieval and evaluation | Semantic retrieval, citation / claim / grounding checks, pytest   |
| Frontend                 | Server-rendered Jinja2 dashboard templates, HTML, CSS, JavaScript |
| Security operations      | JSONL audit and workflow records, monitoring / detection rules    |
| Infrastructure           | Docker, Docker Compose, Windows 11, WSL 2, NVIDIA CUDA            |
| Public portfolio demo    | Render free-tier Docker service, lightweight read-only mode       |

## Run the Full Platform Locally

**Requirements:** Docker Desktop with Docker Compose, sufficient RAM and storage for Qwen3-0.6B, and an internet connection for the initial model download.

```powershell
git clone https://github.com/karmeensec/enterprise-ai-security-lab.git
cd enterprise-ai-security-lab
Copy-Item .env.example .env
```

Configure the variables in `.env` with **your own credentials and secrets**; never commit this file. See [Deployment and Operations](docs/DEPLOYMENT.md) for the environment configuration and operational details.

```powershell
docker compose up -d --build --wait
docker compose ps
curl.exe http://127.0.0.1:8000/health
```

Open **http://127.0.0.1:8000/dashboard/** and authenticate using your configured local dashboard credentials. Docker uses the CPU inference stack; the separate native Windows Python environment can use CUDA on compatible NVIDIA hardware.

To run the existing regression tests from an appropriately configured Python environment:

```powershell
python -m pytest tests/ -q
```

**Public demo:** [Open the read-only security dashboard on Render](https://enterprise-ai-security-lab-apnu.onrender.com/dashboard/). It has intentionally reduced functionality, and free-tier services may take time to wake after inactivity.

## Repository Guide

- `backend/` — FastAPI application, model integration, security validation, agent controls, SOC logic, and deployment utilities
- `dashboard/` — Browser-based SOC and agent security dashboards
- `experiments/` — Development and evaluation experiments
- `tests/` — Automated security, integration, and regression tests
- `results/` — Selected historical experimental evaluation artifacts
- `screenshots/` — Visual evidence from local experiments and dashboards
- `docs/DEPLOYMENT.md` — Deployment, monitoring, backup, and recovery instructions
- `threat_model.md` — Security assumptions, trust boundaries, and threats

## Limitations and Responsible Use

- This is an **independent research and portfolio project**, not an audited production SOC service.
- The hosted Render demo is **public and read-only**, uses no real customer data, and **does not run Qwen inference**. Empty dashboard metrics must not be interpreted as a live security assessment.
- The local version uses HTTP Basic authentication and is bound to localhost through Docker Compose. Public production deployment would require a different identity, session, TLS, CSRF, storage, and operational security design.
- The AI agent cannot carry out real incident-response actions; response workflows are simulated.
- Some dependencies and model downloads are not pinned to immutable artifacts, and JSONL records are not a production multi-node datastore.
- Experimental defenses were evaluated on finite, controlled scenarios; their results do **not** imply complete resistance to prompt injection or model misuse.
- Use adversarial workflows only on systems and data you are authorized to test.

---

**Project status:** Core platform, local Docker deployment, security evaluations, and public read-only dashboard demo implemented. Further development may extend inference deployment, operational persistence, and independent security validation.
