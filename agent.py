"""
The Investigator — Agentic mode (Week 8)

Until now you operated the Investigator step by step. Now you give it a GOAL and
it decides which tools to call to reach a verdict. Your job changes from operator
to supervisor: read what it chose to do, and check whether those choices were sound.

You don't have to write this — but an agent you can't audit is an agent you can't
trust, so read the loop. The pieces worth understanding are marked  #->

Display note: this file uses the `rich` library to show the agent's thinking as a
live, colored trail. `rich` ONLY affects how things look — the agent loop itself is
exactly the plain loop from the lab. Read run_agent() and you'll see it.
"""

import json
import os
import re
from pathlib import Path

from groq import Groq
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

MODEL = "llama-3.3-70b-versatile"   # supports tool use / function calling
EVIDENCE_DIR = "evidence"
SECRETS_PATH = Path(".streamlit/secrets.toml")

console = Console()


def get_groq_api_key():
    """Prefer the user's env var; fall back to local Streamlit secrets (gitignored)."""
    key = (os.environ.get("GROQ_API_KEY") or "").strip()
    # Ignore lab placeholders so a mistaken export doesn't block secrets.toml.
    if key and key.lower() not in {"your_key_here", "gsk_...", "changeme"}:
        return key
    if SECRETS_PATH.is_file():
        match = re.search(
            r'GROQ_API_KEY\s*=\s*["\']([^"\']+)["\']',
            SECRETS_PATH.read_text(encoding="utf-8"),
        )
        if match:
            return match.group(1).strip()
    return None

# ---------------------------------------------------------------------------
# A tiny, offline MITRE reference so the agent can verify technique IDs.
# (In a real tool this would query attack.mitre.org instead.)
# ---------------------------------------------------------------------------
MITRE = {
    "T1110": "Brute Force — guessing credentials through many login attempts.",
    "T1078": "Valid Accounts — abusing existing legitimate credentials.",
    "T1136": "Create Account — creating a new account for persistence.",
    "T1021": "Remote Services — moving laterally using remote access (RDP/SMB).",
    "T1059": "Command and Scripting Interpreter — running commands via a shell.",
    "T1071": "Application Layer Protocol — C2 traffic over common protocols.",
    "T1105": "Ingress Tool Transfer — downloading tools/payloads onto a host.",
    "T1486": "Data Encrypted for Impact — ransomware encrypting files.",
    "T1562": "Impair Defenses — disabling security tools (e.g., antivirus).",
    "T1070": "Indicator Removal — clearing logs to hide activity.",
    "T1560": "Archive Collected Data — staging/compressing data before exfil.",
    "T1048": "Exfiltration Over Alternative Protocol — sending data to an attacker.",
}

# ---------------------------------------------------------------------------
# The three tools the agent is allowed to call.
# ---------------------------------------------------------------------------
def list_evidence():
    if not os.path.isdir(EVIDENCE_DIR):
        return "No evidence/ folder found."
    files = [f for f in os.listdir(EVIDENCE_DIR) if f.endswith((".log", ".txt"))]
    return "\n".join(files) if files else "evidence/ is empty."

def read_log(filename):
    # os.path.basename strips any path, so the agent can't read outside evidence/.
    path = os.path.join(EVIDENCE_DIR, os.path.basename(filename))
    if not os.path.isfile(path):
        return f"No such file: {filename}"
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def lookup_mitre(technique_id):
    key = technique_id.upper().strip()
    return MITRE.get(key, f"{key}: not in local reference — verify at attack.mitre.org")

# #-> The SCHEMA is all the model sees. It never sees the Python above — only
#     these names, descriptions, and argument shapes. That's how it knows what
#     it can call and how.
TOOLS = [
    {"type": "function", "function": {
        "name": "list_evidence",
        "description": "List the log files available in the evidence/ folder.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "read_log",
        "description": "Read the full contents of one evidence log file.",
        "parameters": {"type": "object",
            "properties": {"filename": {"type": "string", "description": "The log file name, e.g. auth_events.log"}},
            "required": ["filename"]},
    }},
    {"type": "function", "function": {
        "name": "lookup_mitre",
        "description": "Look up what a MITRE ATT&CK technique ID means, e.g. T1110.",
        "parameters": {"type": "object",
            "properties": {"technique_id": {"type": "string", "description": "A technique ID like T1059."}},
            "required": ["technique_id"]},
    }},
]

AVAILABLE = {"list_evidence": list_evidence, "read_log": read_log, "lookup_mitre": lookup_mitre}

SYSTEM = """You are an autonomous SOC analyst. Investigate the incident in the
evidence/ folder using the tools available to you. Decide for yourself which logs
to read and which technique IDs to verify. When you have enough to be sure, stop
calling tools and write a final report with: what happened (the attack chain in
order), the hosts/accounts/IPs involved, a MITRE ATT&CK mapping (tactic, technique
name, ID), and a severity (Low/Medium/High/Critical). Only cite evidence you have
actually read. Do not invent log lines or technique IDs."""

# ---------------------------------------------------------------------------
# The agent loop. THIS is what "an agent" actually is: a loop where the model
# picks the next tool, your code runs it, and the result goes back in — until
# the model decides it's done. (The console.* calls are just pretty printing.)
# ---------------------------------------------------------------------------
def run_agent(goal, max_steps=10):
    api_key = get_groq_api_key()
    if not api_key:
        raise SystemExit(_missing_key_message())
    client = Groq(api_key=api_key)

    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": goal}]

    console.rule("[bold blue]🕵️  The Investigator — autonomous run")
    console.print(f"[dim]Goal:[/] {goal}\n")

    for step in range(max_steps):          # #-> bound the loop — never let an agent run forever
        # #-> Ask the model what to do next. The spinner shows it's "thinking".
        with console.status("[bold green]Investigator is thinking...", spinner="dots"):
            resp = client.chat.completions.create(
                model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto")
        msg = resp.choices[0].message
        messages.append(msg)               # remember what the agent said / asked for

        if msg.content:                    # the agent's own narration, if any
            console.print(Panel(msg.content.strip(), title="[italic]agent reasoning",
                                border_style="grey50", expand=False))

        if not msg.tool_calls:             # #-> no tools requested => this is the final verdict
            console.print()
            console.print(Panel(Markdown(msg.content or "(no verdict text)"),
                                title="[bold green]✅ THE INVESTIGATOR'S VERDICT",
                                border_style="green"))
            return

        for tc in msg.tool_calls:          # #-> the agent CHOSE these. Watch what it picks.
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}") or {}   # guard null/empty args
            console.print(f"[bold cyan]├─ step {step + 1}[/]  "
                          f"[bold yellow]{name}[/][white]({args})[/]")
            result = AVAILABLE[name](**args)
            # Show a short preview of what the tool returned, so the trail is auditable.
            preview = str(result).replace("\n", " ")
            if len(preview) > 100:
                preview = preview[:100] + "…"
            console.print(f"[green]│   ↳[/] [dim]{preview}[/]")
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "name": name, "content": str(result)})

    console.print("\n[bold red][stopped: hit the step limit without a final verdict][/]")


def _missing_key_message():
    return (
        "No GROQ_API_KEY found. Provide your own key (do not hard-code it):\n"
        "  export GROQ_API_KEY=gsk_...              # Git Bash / Linux / macOS\n"
        "  $env:GROQ_API_KEY = \"gsk_...\"           # PowerShell\n"
        "  docker run -e GROQ_API_KEY=gsk_... ...   # container\n"
        "Or for local Streamlit+CLI: add GROQ_API_KEY = \"gsk_...\" to "
        ".streamlit/secrets.toml (gitignored)."
    )


if __name__ == "__main__":
    run_agent("Investigate the incident in the evidence/ folder and report what happened.")
