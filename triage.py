from datetime import datetime
from pathlib import Path

import ollama

EVIDENCE_DIR = Path("evidence")
RUNBOOK_PATH = Path("ir_runbook.md")
REPORTS_DIR = Path("reports")
MODEL = "llama3.1:8b"

SYSTEM_PROMPT = """You are a senior SOC analyst. Analyze the provided evidence logs
and incident-response runbook. Produce a Markdown incident report with these
sections:

1. Summary
2. Timeline
3. Root Cause
4. MITRE ATT&CK Mapping — for each finding include tactic, technique name, and technique ID
5. Runbook Steps — which steps were completed vs. missed
6. Recommended Next Actions

Be precise. Base conclusions only on the evidence. If something is unclear, say so.
Do not invent facts."""

# Step 1: Read every log file in the evidence/ folder
evidence_parts = []
for path in sorted(EVIDENCE_DIR.iterdir()):
    if not path.is_file() or path.name.startswith("."):
        continue  # skip directories and .gitkeep
    content = path.read_text(encoding="utf-8")
    evidence_parts.append(f"### {path.name}\n{content.strip()}")

evidence_text = "\n\n".join(evidence_parts)

# Step 2: Read the incident-response runbook
runbook_text = RUNBOOK_PATH.read_text(encoding="utf-8")

# Step 3: Send evidence + runbook to local Llama 3.1 via Ollama
user_prompt = f"""## Evidence Logs

{evidence_text}

## Incident Response Runbook

{runbook_text}

Please produce the Markdown incident report described in your instructions."""

response = ollama.chat(
    model=MODEL,
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ],
)
report = response["message"]["content"]

# Step 4: Ensure reports/ exists, then write a timestamped report file
REPORTS_DIR.mkdir(exist_ok=True)
stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
report_path = REPORTS_DIR / f"report_{stamp}.md"
report_path.write_text(report, encoding="utf-8")

print(f"Wrote incident report to {report_path}")
