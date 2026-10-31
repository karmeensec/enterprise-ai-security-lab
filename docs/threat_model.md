
# Enterprise AI Security Platform
## Threat Model — Version 0.1

**Experiment:** 38  
**Status:** Initial architecture and threat assessment  
**Environment:** Local Windows 11 development lab  
**Classification:** Synthetic research and development system

---

## 1. Purpose

Identify security threats affecting the platform's LLM,
retrieval pipeline, validation services, APIs, logging,
and analyst console.

This model establishes the baseline for subsequent
adversarial experiments and defensive engineering.

## 2. System Scope

### Implemented components

- FastAPI application with chat and RAG endpoints
- Local Qwen-based LLM inference
- SentenceTransformer-based document retrieval
- Synthetic company security-policy knowledge base
- Citation reference validation
- Rule-based and NLI-assisted grounding evaluation
- Hybrid AI security assessment service
- Structured JSONL security audit logging
- Security monitoring and alert correlation
- Authenticated analyst dashboard
- Audit-event filtering and investigation views

### Planned components

- Agentic workflows and tool calling
- MCP integrations
- Enterprise role-based authorization
- Prompt-injection defenses
- RAG document-ingestion security controls
- Centralized monitoring and alert delivery
- Containerized/cloud deployment

Planned capabilities must not be represented as
implemented controls.

## 3. Assets to Protect

| ID | Asset | Security Objective |
|---|---|---|
| AST-01 | System and application instructions | Integrity |
| AST-02 | Retrieved policy documents | Integrity and confidentiality |
| AST-03 | Model inputs and outputs | Confidentiality and integrity |
| AST-04 | Security evaluation decisions | Integrity |
| AST-05 | Monitoring credentials | Confidentiality |
| AST-06 | Security audit records | Integrity and availability |
| AST-07 | Security console | Authorized access |
| AST-08 | Host compute resources | Availability |

## 4. Trust Boundaries

### TB-01: External request to application

Requests from clients must be considered untrusted.

Current controls:
- FastAPI/Pydantic request validation
- Input size limits on selected endpoints
- Request identifiers
- API-key check on monitoring endpoint

Known gaps:
- Security evaluation endpoint is not yet protected
  by enterprise authentication and authorization
- Not all application endpoints have equivalent controls

### TB-02: Retrieved content to LLM

Retrieved documents are data, not trusted instructions.

Current controls:
- Retrieval from a local synthetic policy collection
- Citation and grounding evaluation experiments

Known gaps:
- No comprehensive indirect prompt-injection defense
- No secured document-ingestion workflow
- Citation validity does not guarantee factual support

### TB-03: Model output to security decision

Model-generated content may be incorrect, misleading,
or inconsistent with source material.

Current controls:
- Rule-based grounding checks
- NLI-assisted verification
- Conservative review-required decisions

Known gaps:
- Checks do not prove semantic correctness
- False approvals and false rejections remain possible
- Some checks operate on supplied claims rather than
  enforcing policy over all chat outputs

### TB-04: Security services to audit storage

Security records must remain accurate and available.

Current controls:
- Structured JSONL events
- Limited logged metadata
- Request-ID correlation
- Local monitoring and detection rules

Known gaps:
- Best-effort logging
- No tamper-evident storage
- No centralized retention or backup policy
- No continuous monitoring service

### TB-05: Analyst access to security console

Monitoring information should be accessible only
to authorized analysts.

Current controls:
- Development HTTP Basic authentication
- Monitoring API-key verification
- Server-side audit filtering

Known gaps:
- No enterprise SSO
- No granular RBAC
- No user-specific audit trail
- Not hardened for public deployment

## 5. Initial Threat Register

| ID | Threat | Target | Initial Priority |
|---|---|---|---|
| AI-T001 | Direct prompt injection | LLM instructions | High |
| AI-T002 | Indirect prompt injection through retrieved context | RAG pipeline | High |
| AI-T003 | Knowledge-base poisoning | Retrieved policy content | High |
| AI-T004 | Fabricated or misleading citations | Citation validation | High |
| AI-T005 | Incorrect grounding approval | Security decision service | High |
| AI-T006 | Unauthorized security evaluation access | FastAPI endpoint | High |
| AI-T007 | Audit-log tampering or deletion | Local audit storage | High |
| AI-T008 | Monitoring authentication compromise | Security console | High |
| AI-T009 | Excessive request/resource consumption | Local inference service | Medium |
| AI-T010 | Unsafe agent tool execution | Future agent workflows | Planned |

Priorities are preliminary analyst estimates,
not the results of a completed risk-scoring exercise.

## 6. First Adversarial Test Scenarios

### Scenario 1 — Direct Prompt Injection

Goal:
Determine whether user-supplied instructions can
override the application's intended instruction
hierarchy.

Evidence:
- Controlled test prompts
- Model responses
- Expected versus observed behavior

### Scenario 2 — RAG Prompt Injection

Goal:
Determine whether instructions embedded in retrieved
documents improperly influence the model.

Evidence:
- Original and modified synthetic documents
- Retrieved context
- Model outputs
- Detection and grounding results

### Scenario 3 — Citation Manipulation

Goal:
Determine whether the system accepts a known citation
that fails to support the corresponding claim.

Evidence:
- Submitted claims
- Cited document identifiers
- Citation validation
- Grounding decisions

### Scenario 4 — Security Decision Bypass

Goal:
Identify unsupported or contradictory policy claims
incorrectly approved by the validation service.

Evidence:
- Test dataset
- Expected decisions
- Actual decisions
- False-approval and abstention rates

## 7. Rules of Engagement

All experiments will use local application endpoints,
authorized lab resources, and synthetic policy data.

No real user credentials, private enterprise
documents, or production services are required.

Each experiment will preserve:
- Test objective
- Test input
- Expected behavior
- Actual behavior
- Security finding
- Defensive change
- Regression-test result

## 8. Current Limitations

This is a research prototype, not a production-certified
AI security platform.

The initial threat model must be revisited when agents,
external tools, cloud infrastructure, or additional
data sources are introduced.

## 9. Next Activities

1. Validate the threat register against actual code.
2. Identify existing controls and missing enforcement.
3. Build a controlled prompt-injection evaluation dataset.
4. Establish reproducible baseline attack results.
5. Implement and compare defensive controls.
