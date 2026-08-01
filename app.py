"""
The Investigator — SOC Copilot (v1.2)
Correlates multiple log sources into one verdict using Groq (Llama 3.3 70B),
with a deterministic pre-pass before the LLM, Case Files, and an autonomous
tool-calling agent over evidence/.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import streamlit as st
from groq import Groq

from prepass import case_metadata_footer, hash_evidence, run_prepass, run_prepass_on_dir

REPORTS_DIR = Path("reports")
RUNBOOK_PATH = Path("ir_runbook.md")
EVIDENCE_DIR = Path("evidence")
SECRETS_PATH = Path(".streamlit/secrets.toml")
MODEL = "llama-3.3-70b-versatile"

CORRELATION_SYSTEM_PROMPT = """You are a senior SOC analyst. You are given raw log
files, an incident-response runbook, and a DETERMINISTIC PRE-PASS summary produced
by code (not by you). Correlate into ONE incident and produce a Markdown report
with these exact sections:

## 1. Threat Analysis
What happened, the attack chain in order, and the hosts, accounts, and IPs involved.
Cite concrete log lines or pre-pass facts for each major claim.

## 2. MITRE ATT&CK Mapping
For each finding include: tactic, technique name, technique ID (e.g., T1059),
confidence (High / Medium / Low), and a one-line confidence note.
Do not invent technique IDs that are not supported by the logs or pre-pass.

## 3. Severity
One of Low / Medium / High / Critical, with a one-line justification.
Assign Critical ONLY if at least two independent sources support meaningful impact
(e.g. encryption/ransom + successful auth, or pre-pass brute-force flag + confirmed
compromise). Otherwise cap at High and add a **FLAG:** explaining why Critical
was not assigned.

## 4. Investigation Plan
Concrete next steps to confirm scope.

## 5. Response Plan
Containment, eradication, and recovery steps aligned with the runbook.
Prefix every disruptive step with **RECOMMEND — verify before action:**
(isolate host, block IP, disable account, etc.). Never imply automated containment.

## 6. Uncertainties & Flags
Gaps, conflicts, thin evidence, or conclusions that need human verification.
Prefix each item with **FLAG:**
Reconcile with the deterministic pre-pass: if you disagree with a pre-pass fact,
explain why under Flags — do not silently ignore it.

Cite specific log evidence or pre-pass bullets for each claim. If uncertain, say so."""


def get_groq_api_key() -> str | None:
    """Prefer env var (Cloud / Docker / CLI); fall back to local secrets.toml."""
    key = (os.environ.get("GROQ_API_KEY") or "").strip()
    if key and key.lower() not in {"your_key_here", "gsk_...", "changeme"}:
        return key
    try:
        return st.secrets["GROQ_API_KEY"]
    except Exception:
        pass
    if SECRETS_PATH.is_file():
        match = re.search(
            r'GROQ_API_KEY\s*=\s*["\']([^"\']+)["\']',
            SECRETS_PATH.read_text(encoding="utf-8"),
        )
        if match:
            return match.group(1).strip()
    return None


def ask_groq(messages):
    api_key = get_groq_api_key()
    if not api_key:
        return (
            "⚠️ No GROQ_API_KEY found. Set it in Streamlit Cloud Secrets, "
            "export GROQ_API_KEY, or add it to local `.streamlit/secrets.toml`."
        )
    try:
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(model=MODEL, messages=messages)
        return resp.choices[0].message.content
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
        "Do not invent facts. Recommend verifying before any containment action."
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
    st.session_state.pop("prepass", None)
    st.session_state.chat = []
    st.session_state.uploader_key = st.session_state.get("uploader_key", 0) + 1


# ===========================================================================
# AGENT MACHINERY — same loop as agent.py; trail renders in the UI.
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
evidence/ folder using the tools available to you. Prefer calling run_prepass early
for deterministic facts, then decide which logs to read and which technique IDs to
verify. When you have enough to be sure, stop calling tools and write a final report
with: attack chain, hosts/accounts/IPs, MITRE mapping (with confidence High/Medium/Low
per finding), and severity (Critical only with multi-source support). Only cite
evidence you have actually read. Label containment as recommendations to verify
before action. Do not invent log lines or technique IDs."""


def list_evidence():
    if not EVIDENCE_DIR.is_dir():
        return "No evidence/ folder found."
    files = sorted(
        p.name for p in EVIDENCE_DIR.iterdir()
        if p.is_file() and p.suffix in (".log", ".txt")
    )
    return "\n".join(files) if files else "evidence/ is empty."


def read_log(filename):
    path = EVIDENCE_DIR / Path(filename).name
    if not path.is_file():
        return f"No such file: {filename}"
    return path.read_text(encoding="utf-8", errors="ignore")


def lookup_mitre(technique_id):
    key = technique_id.upper().strip()
    return MITRE.get(key, f"{key}: not in local reference — verify at attack.mitre.org")


def tool_run_prepass():
    return run_prepass_on_dir(EVIDENCE_DIR)


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
    {"type": "function", "function": {
        "name": "run_prepass",
        "description": "Run deterministic failed-login, beaconing, and timeline checks on evidence/.",
        "parameters": {"type": "object", "properties": {}},
    }},
]

AVAILABLE = {
    "list_evidence": list_evidence,
    "read_log": read_log,
    "lookup_mitre": lookup_mitre,
    "run_prepass": tool_run_prepass,
}


def run_agent(goal, max_steps=10):
    """The loop from agent.py, writing its trail to the page instead of the terminal."""
    api_key = get_groq_api_key()
    if not api_key:
        return (
            "⚠️ No GROQ_API_KEY found. Set Streamlit Cloud Secrets, export "
            "GROQ_API_KEY, or use local `.streamlit/secrets.toml`."
        )

    client = Groq(api_key=api_key)
    messages = [{"role": "system", "content": AGENT_SYSTEM},
                {"role": "user", "content": goal}]
    trail: list[str] = []

    for step in range(max_steps):
        try:
            resp = client.chat.completions.create(
                model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto")
        except Exception as e:
            return f"⚠️ Groq request failed: {e}"

        msg = resp.choices[0].message
        messages.append(msg)

        if msg.content:
            st.markdown(f"💭 {msg.content.strip()}")

        if not msg.tool_calls:
            verdict = msg.content or "_(no verdict text)_"
            if trail:
                verdict += "\n\n---\n\n## Agent trail\n\n" + "\n".join(f"- {t}" for t in trail)
            return verdict

        for tc in msg.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}") or {}
            st.write(f"🔧 **step {step + 1}** · `{name}({args})`")
            if name not in AVAILABLE:
                result = f"Unknown tool: {name}"
            else:
                try:
                    result = AVAILABLE[name](**args)
                except TypeError as e:
                    result = f"Bad arguments for {name}: {e}"
            preview = str(result).replace("\n", " ")
            if len(preview) > 100:
                preview = preview[:100] + "…"
            st.caption(f"↳ {preview}")
            trail.append(f"step {step + 1}: `{name}({args})` → {preview}")
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "name": name, "content": str(result)})

    return "_(stopped: hit the step limit without a verdict)_"


st.set_page_config(page_title="The Investigator v1.2 — SOC Copilot", page_icon="🕵️")
st.title("🕵️ The Investigator v1.2 — SOC Copilot")
st.caption(
    "Deterministic pre-pass, then LLM correlation — load a Case File, ask follow-ups, "
    "or run Autonomous Investigation. Containment is recommend-only."
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
    st.caption(
        "Upload one or more logs. A deterministic pre-pass runs first; then the "
        "Copilot correlates into a single verdict that must reconcile with those facts."
    )

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
            file_map: dict[str, str] = {}
            combined = ""
            for f in uploaded:
                text = f.read().decode("utf-8", errors="ignore")
                file_map[f.name] = text
                combined += f"\n\n===== {f.name} =====\n{text}"

            prepass_md = run_prepass(file_map)
            overall_hash, _ = hash_evidence(file_map)
            st.session_state.prepass = prepass_md

            user_content = (
                f"## Incident-response runbook\n\n{runbook}\n\n"
                f"{prepass_md}\n\n"
                f"## Evidence logs\n{combined}"
            )
            with st.spinner("Running pre-pass, then correlating across sources..."):
                report = ask_groq([
                    {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ])

            if report and not report.startswith("⚠️"):
                report = report + case_metadata_footer(
                    model=MODEL,
                    file_names=sorted(file_map),
                    evidence_sha256=overall_hash,
                    prepass_excerpt=prepass_md,
                )

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

    if st.session_state.get("prepass"):
        with st.expander("Deterministic pre-pass (rule-based)", expanded=True):
            st.markdown(st.session_state.prepass)

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
        f"It investigates the logs already in your **`{EVIDENCE_DIR}/`** folder "
        "(list/read logs, MITRE lookup, deterministic `run_prepass`). "
        "Read the trail, then check the verdict. Containment stays recommend-only."
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
            "Supervise it: did it run pre-pass or read every relevant log, verify "
            "MITRE IDs, and invent nothing?"
        )
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        st.download_button(
            "⬇️ Download verdict",
            st.session_state.verdict,
            file_name=f"autonomous_verdict_{stamp}.md",
        )
