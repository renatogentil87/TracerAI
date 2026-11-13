# TracerAI

**TracerAI** is an AI-powered AWS networking troubleshooting agent. It is built with the **Strands Agents SDK** (code-first, Python) on **Amazon Bedrock**, and uses **read-only** `boto3` tools to inspect live network infrastructure — starting with **EC2 Reachability Analyzer** — then explains *why* connectivity works or fails in plain language.

> ⚠️ **Proof of Concept / learning project** — under active development.

## What it does

Ask a natural-language question like *"Can instance A reach instance B on port 3306?"* The agent calls the right read-only AWS API (Reachability Analyzer), reads the structured result, and returns a diagnosis (reachable or not, and *why* — e.g. a security-group mismatch or a missing route).

## Architecture (Strands, code-first)

The agent loop runs **in your Python process** — no managed Bedrock Agent, no Lambda, no OpenAPI schema required to run locally:

1. **CLI / entry point** — you ask a question (`python -m tracerai.agent`).
2. **Strands Agent** — the orchestrator. It uses a Bedrock model to decide which tool to call.
3. **Tools (`tracerai/tools/`)** — plain `boto3` functions (the "hands"). Each is independently testable without the LLM.
4. **AWS (read-only)** — the tools run analysis/describe APIs against the target account via a read-only role.

> **Deployment (later):** Strands agents can be hosted on Bedrock AgentCore Runtime, Lambda, or Fargate. That is a *later* step — development starts local.

## Repository layout

| Path | Purpose |
|------|---------|
| `tracerai/` | Python package (the agent) |
| `tracerai/tools/reachability.py` | **M0** — Reachability Analyzer tool (plain boto3, runnable standalone) |
| `tracerai/agent.py` | **M1** — wires the tool into a Strands agent |
| `requirements.txt` | Dependencies (boto3; Strands added at M1) |
| `docs/` | Architecture diagram and notes |
| `lambdas/`, `schema/` | **Legacy** — scaffolding from the earlier Bedrock-Agents approach; not used by the Strands build (safe to delete) |

## Milestones

| | Goal |
|---|------|
| **M0** | `reachability(src, dst, port)` works standalone and returns a clean result dict |
| **M1** | Strands agent answers one question end-to-end by calling the tool |
| **M2** | Resolve friendly names → instance IDs (add a describe-instances tool) |
| **M3** | Interpret ExplanationCodes into plain-English remediation |
| **M4** | Add a second tool (e.g. describe-security-groups) for deeper analysis |

## Getting started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install boto3

# M0 — run the tool directly (no AI yet):
python tracerai/tools/reachability.py
```
Point your shell at a **Bedrock-allowed sandbox account / read-only role** before running. For M1, install the Strands package (**verify the exact name in the current Strands docs**) and run `python -m tracerai.agent`.

## Security

All AWS calls are **read-only / analysis** by design. The agent's role needs only:
`ec2:CreateNetworkInsightsPath`, `ec2:StartNetworkInsightsAnalysis`, `ec2:DescribeNetworkInsightsAnalyses`, `ec2:DeleteNetworkInsightsPath` (cleanup), and `ec2:Describe*`. **No mutating network permissions** — TracerAI diagnoses, it never changes infrastructure.

## License

TBD
