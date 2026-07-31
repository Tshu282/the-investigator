"""
The Investigator — SOC Copilot (Week 8)
A Streamlit app that correlates multiple log sources into one verdict using a
hosted LLM (Groq / Llama 3.3 70B), surfaces saved reports in a Case Files tab,
and can investigate the evidence/ folder autonomously with a tool-calling agent.
"""

import json
from datetime import datetime
from pathlib import Path

import streamlit as st
from groq import Groq

REPORTS_DIR = Path("reports")
RUNBOOK_PATH = Path("ir_runbook.md")
EVIDENCE_DIR = Path("evidence")
MODEL = "llama-3.3-70b-versatile"

CORRELATION_SYSTEM_PROMPT = """You are a senior SOC analyst. You are given one or
more raw log files from a single environment, plus an incident-response runbook.
Correlate the logs into ONE incident and produce a Markdown report with these
exact sections:

## 1. Threat Analysis
What happened, the attack chain in order, and the hosts, accounts, and IPs involved.

## 2. MITRE ATT&CK Mapping
For each finding: tactic, technique name, and technique ID (e.g., T1059).

## 3. Severity
One of Low / Medium / High / Critical, with a one-line justification.

## 4. Investigation Plan
Concrete next steps to confirm scope.

## 5. Response Plan
Containment, eradication, and recovery steps aligned with the provided runbook phases.

## 6. Uncertainties & Flags
List anything you are unsure about, gaps in evidence, conflicting timestamps, or
conclusions that need human verification. Prefix each item with **FLAG:**

Cite the specific log evidence for each claim. If something is uncertain, say so —
do not invent technique IDs or events that are not present in the logs."""


def ask_groq(messages):
    try:
        client = Groq(api_key=st.secrets["GROQ_API_KEY"])
        resp = client.chat.completions.create(model=MODEL, messages=messages)
        return resp.choices[0].message.content
    except KeyError:
        return "⚠️ No GROQ_API_KEY found. Add it to .streamlit/secrets.toml and rerun."
    except Exception as e:
        return f"⚠️ Groq request failed: {e}"


def load_runbook():
    if not RUNBOOK_PATH.is_file():
        return None
    return RUNBOOK_PATH.read_text(encoding="utf-8")


def save_report(report: str):
    """Best-effort write under reports/. May fail or not persist on Streamlit Cloud."""
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        path = REPORTS_DIR / f"triage_report_{stamp}.md"
        path.write_text(report, encoding="utf-8")
        return path
    except OSError as e:
        return e


def list_case_files():
    """Return .md filenames in reports/, newest modified first."""
    if not REPORTS_DIR.is_dir():
        return []
    paths = [p for p in REPORTS_DIR.iterdir() if p.is_file() and p.suffix == ".md"]
    paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [p.name for p in paths]


def chat_system_prompt(report: str | None) -> str:
    base = (
        "You are a senior SOC analyst helping a colleague. Be concise and precise. "
        "Do not invent facts."
    )
    if report:
        return (
            f"{base}\n\nAn active correlation report is in context. Use it to answer "
            f"questions about this case (hosts, accounts, MITRE mappings, severity, "
            f"next steps). If the report does not support an answer, say so.\n\n"
            f"--- ACTIVE CASE REPORT ---\n{report}"
        )
    return (
        f"{base} No active case report is loaded yet — suggest Correlate & Triage "
        f"or load a report from Case Files if the question is case-specific."
    )


def active_case_label() -> str | None:
    if not st.session_state.get("report"):
        return None
    name = st.session_state.get("active_case_file")
    return name if name else "Live correlation (Tab 1)"


def reset_case():
    st.session_state.pop("report", None)
    st.session_state.pop("report_path", None)
    st.session_state.pop("active_case_file", None)
    st.session_state.chat = []
    st.session_state.uploader_key = st.session_state.get("uploader_key", 0) + 1


# ===========================================================================
# AGENT MACHINERY — the same loop, tools, and schema as the CLI agent
# (agent.py). Only the edges differ: the key comes from st.secrets and the
# trail is written to the page instead of the terminal. An agent is the loop,
# not the interface.
# ===========================================================================
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

AGENT_SYSTEM = """You are an autonomous SOC analyst. Investigate the incident in the
evidence/ folder using the tools available to you. Decide for yourself which logs
to read and which technique IDs to verify. When you have enough to be sure, stop
calling tools and write a final report with: what happened (the attack chain in
order), the hosts/accounts/IPs involved, a MITRE ATT&CK mapping (tactic, technique
name, ID), and a severity (Low/Medium/High/Critical). Only cite evidence you have
actually read. Do not invent log lines or technique IDs."""


def list_evidence():
    if not EVIDENCE_DIR.is_dir():
        return "No evidence/ folder found."
    files = sorted(
        p.name for p in EVIDENCE_DIR.iterdir()
        if p.is_file() and p.suffix in (".log", ".txt")
    )
    return "\n".join(files) if files else "evidence/ is empty."


def read_log(filename):
    # Path(...).name strips any directory part, so the agent cannot read outside evidence/.
    path = EVIDENCE_DIR / Path(filename).name
    if not path.is_file():
        return f"No such file: {filename}"
    return path.read_text(encoding="utf-8", errors="ignore")


def lookup_mitre(technique_id):
    key = technique_id.upper().strip()
    return MITRE.get(key, f"{key}: not in local reference — verify at attack.mitre.org")


# The schema is all the model sees — never the Python above. These names,
# descriptions, and argument shapes are how it knows what it may call.
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


def run_agent(goal, max_steps=10):
    """The loop from agent.py, writing its trail to the page instead of the terminal."""
    try:
        client = Groq(api_key=st.secrets["GROQ_API_KEY"])
    except KeyError:
        return "⚠️ No GROQ_API_KEY found. Add it to `.streamlit/secrets.toml` or your app's Secrets."

    messages = [{"role": "system", "content": AGENT_SYSTEM},
                {"role": "user", "content": goal}]

    for step in range(max_steps):        # bound the loop — never let an agent run forever
        try:
            resp = client.chat.completions.create(
                model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto")
        except Exception as e:
            return f"⚠️ Groq request failed: {e}"

        msg = resp.choices[0].message
        messages.append(msg)

        if msg.content:                  # the agent's own narration, if any
            st.markdown(f"💭 {msg.content.strip()}")

        if not msg.tool_calls:           # no tool wanted => this is the final verdict
            return msg.content or "_(no verdict text)_"

        for tc in msg.tool_calls:        # the agent CHOSE these — show the trail
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}") or {}
            st.write(f"🔧 **step {step + 1}** · `{name}({args})`")
            result = AVAILABLE[name](**args)
            preview = str(result).replace("\n", " ")
            if len(preview) > 100:
                preview = preview[:100] + "…"
            st.caption(f"↳ {preview}")
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "name": name, "content": str(result)})

    return "_(stopped: hit the step limit without a verdict)_"


st.set_page_config(page_title="The Investigator v1.2 — SOC Copilot", page_icon="🕵️")
st.title("🕵️ The Investigator v1.2 — SOC Copilot")
st.caption(
    "Correlate logs into one verdict, load a saved Case File as the active case, "
    "then ask follow-ups under Ask the Investigator."
)

if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0
if "chat" not in st.session_state:
    st.session_state.chat = []

tab1, tab2, tab3, tab4 = st.tabs(
    ["Correlate & Triage", "Ask the Investigator", "Case Files", "Autonomous Investigation"]
)

# ---------------------------------------------------------------------------
# TAB 1 — Correlate & Triage
# ---------------------------------------------------------------------------
with tab1:
    st.subheader("Correlate & Triage")
    st.caption("Upload one or more logs. The Copilot correlates them into a single verdict.")

    uploaded = st.file_uploader(
        "Upload log files",
        accept_multiple_files=True,
        key=f"uploader_{st.session_state.uploader_key}",
    )

    if st.button("Run correlation", disabled=not uploaded):
        runbook = load_runbook()
        if runbook is None:
            st.error("`ir_runbook.md` not found. Add it to the project root and try again.")
        else:
            combined = ""
            for f in uploaded:
                text = f.read().decode("utf-8", errors="ignore")
                combined += f"\n\n===== {f.name} =====\n{text}"
            user_content = (
                f"## Incident-response runbook\n\n{runbook}\n\n"
                f"## Evidence logs\n{combined}"
            )
            with st.spinner("Correlating across sources..."):
                report = ask_groq([
                    {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ])
            st.session_state.report = report
            st.session_state.active_case_file = None
            st.session_state.pop("report_path", None)
            if report and not report.startswith("⚠️"):
                saved = save_report(report)
                if isinstance(saved, Path):
                    st.session_state.report_path = str(saved)
                    st.session_state.active_case_file = saved.name
                else:
                    st.warning(
                        f"Could not save to `{REPORTS_DIR}/` ({saved}). "
                        "Use Download — especially on a public Cloud deploy."
                    )

    if st.session_state.get("report"):
        st.markdown(st.session_state.report)
        if st.session_state.get("report_path"):
            st.caption(f"Saved to `{st.session_state.report_path}`")
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        st.download_button(
            "⬇️ Download report",
            st.session_state.report,
            file_name=f"triage_report_{stamp}.md",
        )
        if st.button("Start new analysis"):
            reset_case()
            st.rerun()

# ---------------------------------------------------------------------------
# TAB 2 — Ask the Investigator (chat)
# ---------------------------------------------------------------------------
with tab2:
    st.subheader("Ask the Investigator")
    label = active_case_label()
    if label:
        st.caption(f"Active case loaded into this chat: `{label}`")
    else:
        st.caption(
            "No active report yet — run Correlate & Triage, or open Case Files "
            "and click “Use as active case for chat.”"
        )

    if st.button("Clear chat"):
        st.session_state.chat = []
        st.rerun()

    for msg in st.session_state.chat:
        st.chat_message(msg["role"]).markdown(msg["content"])

    question = st.chat_input("Ask about the case or SOC analysis...")
    if question:
        st.session_state.chat.append({"role": "user", "content": question})
        st.chat_message("user").markdown(question)
        with st.spinner("Thinking..."):
            answer = ask_groq(
                [{"role": "system", "content": chat_system_prompt(st.session_state.get("report"))}]
                + st.session_state.chat
            )
        st.session_state.chat.append({"role": "assistant", "content": answer})
        st.chat_message("assistant").markdown(answer)

# ---------------------------------------------------------------------------
# TAB 3 — Case Files (browse saved reports)
# ---------------------------------------------------------------------------
with tab3:
    st.subheader("Case Files")
    st.caption(
        f"Markdown reports from `{REPORTS_DIR}/`, newest modified first. "
        "Load one as the active case so Ask the Investigator can use it. "
        "On a public Cloud URL this folder is shared and may not persist — "
        "use Download for a private copy of a live correlation."
    )

    md_files = list_case_files()

    if not md_files:
        st.info("No case files yet. Reports saved to `reports/` will appear here.")
    else:
        choice = st.selectbox("Pick a case file", md_files, key="case_file_choice")
        path = REPORTS_DIR / choice
        content = path.read_text(encoding="utf-8")

        if st.session_state.get("active_case_file") == choice:
            st.success(f"`{choice}` is the active case for Ask the Investigator.")
        if st.button("Use as active case for chat"):
            st.session_state.report = content
            st.session_state.active_case_file = choice
            st.session_state.report_path = str(path)
            st.rerun()

        st.markdown(content)

# ---------------------------------------------------------------------------
# TAB 4 — Autonomous Investigation (the agent, in the browser)
# ---------------------------------------------------------------------------
with tab4:
    st.subheader("Autonomous Investigation")
    st.caption(
        "Hand the Investigator a goal and watch it choose its own steps — then audit the trail."
    )
    st.write(
        f"It investigates the logs already in your **`{EVIDENCE_DIR}/`** folder, deciding for "
        "itself which to read and which techniques to verify. Read the trail, then check the verdict."
    )

    goal = st.text_input(
        "Goal",
        value="Investigate the incident in the evidence/ folder and report what happened.",
    )

    if st.button("🕵️ Run autonomous investigation"):
        with st.status("The Investigator is working…", expanded=True):
            verdict = run_agent(goal)
        st.session_state.verdict = verdict

    if st.session_state.get("verdict"):
        st.markdown("### Verdict")
        st.markdown(st.session_state.verdict)
        st.caption(
            "Supervise it: did it read every relevant log, verify its MITRE IDs, and invent nothing?"
        )
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        st.download_button(
            "⬇️ Download verdict",
            st.session_state.verdict,
            file_name=f"autonomous_verdict_{stamp}.md",
        )
