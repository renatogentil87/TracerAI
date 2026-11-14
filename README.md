# TracerAI

TracerAI is a networking troubleshooting agent for AWS. It is built with the Strands Agents SDK on Amazon Bedrock and uses read-only `boto3` tools to inspect live network infrastructure, starting with EC2 Reachability Analyzer, then explains why connectivity works or fails in plain language.

## What it does

Ask a question like "Can the web server reach the database on 3306?" The agent resolves instance names to ids, runs Reachability Analyzer, reads the structured result, and returns a diagnosis: reachable or not, and why (for example a security-group mismatch or a missing route).

## Architecture

The agent loop runs in your Python process.

1. Entry point: you ask a question (`python -m tracerai.agent`).
2. Strands agent: decides which tool to call, using a Bedrock model.
3. Tools (`tracerai/tools/`): plain `boto3` functions, each runnable on its own.
4. AWS: the tools run analysis and describe APIs against the target account.

## Repository layout

| Path | Purpose |
|------|---------|
| `tracerai/` | Python package |
| `tracerai/agent.py` | Strands agent and tool wiring |
| `tracerai/tools/reachability.py` | Reachability Analyzer wrapper |
| `tracerai/tools/instances.py` | Resolve a Name tag to an instance id |
| `requirements.txt` | Dependencies |
| `docs/` | Architecture diagram and notes |

## Getting started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export AWS_PROFILE=<profile>
export AWS_REGION=<region of the instances>

python -m tracerai.agent
```

Run a tool on its own to test it:

```bash
python tracerai/tools/reachability.py
python tracerai/tools/instances.py
```

## Security

All AWS calls are read-only or analysis only. The agent role needs:
`ec2:CreateNetworkInsightsPath`, `ec2:StartNetworkInsightsAnalysis`, `ec2:DescribeNetworkInsightsAnalyses`, `ec2:DeleteNetworkInsightsPath`, and `ec2:Describe*`. No mutating network permissions.

## License

TBD
