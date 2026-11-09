# Enterprise AI Security Lab

**A locally deployed AI security research platform for evaluating and defending retrieval-augmented generation (RAG), LLM agents, and cybersecurity workflows.**

This independent project combines a local instruction-tuned language model, security-focused APIs, document retrieval, authorization controls, attack simulations, audit logging, and SOC-style monitoring. The platform is designed for repeatable security experiments and portfolio demonstrations—not as an independently audited production security system.

## Highlights

- **Local AI inference:** Qwen3-0.6B running with PyTorch and Hugging Face Transformers; CUDA acceleration on an NVIDIA RTX 3050 or CPU inference in Docker.
- **Retrieval-augmented generation:** Security-policy retrieval, citation and grounding validation, and evaluations of answer accuracy.
- **LLM security research:** Direct and indirect prompt injection, poisoned documents, adversarial grounding, and defense comparisons.
- **Agent tool security:** Explicit server-side authorization, validated tool calls, constrained proposals, and simulation-only response actions.
- **Security operations:** Monitoring, security audit records, investigation cases, response plans, and dedicated agent security dashboard.
- **Deployment and operations:** FastAPI, Docker Compose, non-root execution, localhost-only binding, persistent local volumes, backup/restore validation, and deployment-readiness checks.

## Architecture

```text
                        Authenticated browser / API client
                                      |
                                      v
                           FastAPI application
                         backend.secured_app:app
                                      |
                  +-------------------+-------------------+
                  |                   |                   |
                  v                   v                   v
           SOC dashboard       AI agent endpoint     Security monitoring
                  |                   |                   |
                  |                   v                   |
                  |             Qwen3-0.6B model          |
                  |                   |                   |
                  |           Validated tool proposal     |
                  |                   |                   |
                  |         Server-side authorization     |
                  |                   |                   |
                  |     +-------------+-------------+     |
                  |     |             |             |     |
                  |  Policy       Investigation   Response|
                  |  search       /timeline       proposal|
                  |     |             |        (simulation only)
                  |     v             |             |     |
                  |  Trusted         |             |     |
                  |  documents       |             |     |
                  +-----+-------------+-------------+-----+
                        |
                        v
                JSONL audit and case records
                (persistent Docker volumes)
```

The model proposes actions, but **authorization and tool execution are controlled by application code**, not by model output. The platform does not perform real account disabling, host isolation, or other autonomous incident-response actions.

## Technology

| Area               | Technologies                                               |
| ------------------ | ---------------------------------------------------------- |
| Language / backend | Python 3.12, FastAPI                                       |
| Language model     | Qwen/Qwen3-0.6B, PyTorch, Hugging Face Transformers        |
| Acceleration       | NVIDIA CUDA (local Windows), CPU-only PyTorch (Docker)     |
| Application        | REST APIs, browser-based SOC and agent dashboards          |
| Evaluation         | pytest, reproducible experimental scripts and JSON reports |
| Deployment         | Docker, Docker Compose, WSL 2 on Windows                   |
| Logging / state    | JSONL audit records, persistent local Docker volumes       |

## Verified Results

The measurements below are **observations from this development environment**, not performance guarantees for other machines.

### Model inference benchmark — Experiment 64

Same Qwen3-0.6B model and prompt, with one warm-up and three measured generations per environment. Generation used the application's sampling configuration and a 96-token cap.

| Metric                      | Windows / RTX 3050 CUDA |      Docker / CPU |
| --------------------------- | ----------------------: | ----------------: |
| Aggregate throughput        |      **12.08 tokens/s** | **5.78 tokens/s** |
| Average generation time     |                 7.917 s |          16.205 s |
| Process RAM after benchmark |             3,179.59 MB |          3,147 MB |
| Peak CUDA allocated memory  |             1,177.32 MB |               N/A |

The GPU provided **approximately 2.09× throughput** in this workload. The first Docker model-load measurement included downloading model files and is not directly comparable to a cached GPU load.

### Validation

- **547 automated tests passed** at the completion of Experiment 65.
- **22/22 deployment-readiness checks passed** for the local development baseline.
- Docker deployment verified healthy with an unprivileged user, reduced Linux capabilities, and loopback host-port binding.
- CPU and GPU Qwen inference were both executed and measured, rather than mocked.

## Running Locally

### Requirements

- Docker Desktop with Docker Compose
- Memory and disk space sufficient for a CPU-hosted 0.6B-parameter language model
- An internet connection for initial model downloads

1. Clone the repository and enter the project folder.
2. Copy `.env.example` to `.env` and configure **strong, private credentials** and the other documented environment settings. Do not commit `.env`.
3. Build and start the container:

```powershell
docker compose up -d --build --wait
```

4. Check container health:

```powershell
docker compose ps
curl.exe http://127.0.0.1:8000/health
```

5. Open the locally hosted dashboard at `http://127.0.0.1:8000/dashboard/` and authenticate using the configured credentials.

> The full local Docker image supports CPU inference. The locally configured Windows Python environment can use CUDA separately. Initial model downloads and inference can take time.

For operational procedures, including shutdown, backups, recovery, and troubleshooting, see [Deployment and Operations](docs/DEPLOYMENT.md).

## Research Areas

This repository contains experiments involving:

- **RAG and grounded generation:** Retrieval quality, source citation checks, and claim verification.
- **Adversarial LLM inputs:** Direct prompt injection, indirect attacks through retrieved material, and poisoned policy documents.
- **Defense evaluation:** Grounding strategies, response policy checks, and comparison of security outcomes across configurations.
- **Agentic security:** Tool-call parsing, least-privilege access, role enforcement, auditing, and red-team scenarios.
- **SOC workflows:** Security events, monitoring, investigation records, response planning, and backup integrity.

Evaluation scripts and historical result files document the development process. Treat measured outcomes as specific to the tested prompts, data, configurations, and versions.

## Security Boundaries and Limitations

- This is a **research and demonstration system**, not a production-grade SOC or a replacement for analyst judgment.
- AI-proposed response operations are **simulation only**; the model is not authorized to execute real response actions.
- The local deployment uses HTTP Basic authentication and a loopback-only host port. Internet-facing use requires additional authentication, TLS, and deployment-specific review.
- Docker CPU dependencies and model artifacts are not yet fully pinned to immutable versions or hashes.
- Local JSONL storage and Docker volumes are not a managed production database or disaster-recovery service.
- Any public demonstration should disable unsupported AI features rather than inventing simulated outputs, and should not expose private logs or security data.
- Readiness checks assess specified local configuration properties; they are **not** a penetration test or certification of production security.

## Documentation

- [Deployment and Operations](docs/DEPLOYMENT.md)
- [Threat Model](threat_model.md)
- Historical experiments and evaluation results are available in the corresponding project directories.
