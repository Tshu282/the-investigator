"""
The Investigator — SOC Copilot
Correlates multiple log sources into one incident verdict using Groq (Llama 3.3 70B),
aligned with the project's IR runbook.
"""

import re
from datetime import datetime
from pathlib import Path

import streamlit as st
from groq import Groq

MODEL = "llama-3.3-70b-versatile"
RUNBOOK_PATH = Path("ir_runbook.md")
SAMPLES_DIR = Path("samples")
REPORTS_DIR = Path("reports")

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
Put the severity word on its own line or clearly as the first word after the heading
so it can be parsed (e.g., **High** — justification).

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


def list_sample_files():
    if not SAMPLES_DIR.is_dir():
        return []
    return sorted(
        p for p in SAMPLES_DIR.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )


def parse_severity(report: str) -> str | None:
    match = re.search(
        r"##\s*3\.\s*Severity\s*\n+([^\n]+)",
        report,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    line = match.group(1)
    for level in ("Critical", "High", "Medium", "Low"):
        if re.search(rf"\b{level}\b", line, flags=re.IGNORECASE):
            return level
    return None


def severity_badge(level: str):
    colors = {
        "Low": ("#1b5e20", "#e8f5e9"),
        "Medium": ("#e65100", "#fff3e0"),
        "High": ("#b71c1c", "#ffebee"),
        "Critical": ("#ffffff", "#4a0000"),
    }
    fg, bg = colors.get(level, ("#111", "#eee"))
    st.markdown(
        f'<div style="display:inline-block;padding:0.35rem 0.85rem;'
        f'border-radius:6px;font-weight:700;letter-spacing:0.04em;'
        f'color:{fg};background:{bg};margin-bottom:0.75rem;">'
        f"SEVERITY: {level.upper()}</div>",
        unsafe_allow_html=True,
    )


def save_report(report: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    path = REPORTS_DIR / f"triage_report_{stamp}.md"
    path.write_text(report, encoding="utf-8")
    return path


def reset_case():
    st.session_state.pop("report", None)
    st.session_state.pop("report_path", None)
    st.session_state.chat = []
    st.session_state.sample_multiselect = []
    st.session_state.uploader_key = st.session_state.get("uploader_key", 0) + 1


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
        f"{base} No correlation report is loaded yet — suggest the analyst run "
        f"Correlate & Triage first if the question is case-specific."
    )


st.set_page_config(page_title="The Investigator — SOC Copilot", page_icon="🕵️")
st.title("🕵️ The Investigator — SOC Copilot")
st.caption(
    "An AI-powered security & network analyst — correlate logs into one verdict, "
    "then ask follow-up questions about the case."
)

with st.sidebar:
    st.header("About")
    st.markdown(
        "Built for junior analysts who need a fast first pass across messy logs — "
        "then clear next steps before acting."
    )
    st.markdown(
        "**Correlate & Triage** — upload or load sample logs; get one incident "
        "report with MITRE mapping, severity, and runbook-aligned response steps."
    )
    st.markdown(
        "**Ask the Investigator** — chat about SOC analysis. When a report exists, "
        "questions stay grounded in that case."
    )

if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0
if "chat" not in st.session_state:
    st.session_state.chat = []

tab1, tab2 = st.tabs(["Correlate & Triage", "Ask the Investigator"])

# ---------------------------------------------------------------------------
# TAB 1 — Correlate & Triage
# ---------------------------------------------------------------------------
with tab1:
    st.subheader("Correlate & Triage")
    st.caption("Upload logs and/or load samples. The Copilot correlates them into a single verdict.")

    sample_files = list_sample_files()
    selected_samples = []
    if sample_files:
        st.markdown("**Sample logs**")
        sample_names = [p.name for p in sample_files]
        selected_samples = st.multiselect(
            "Load from samples/",
            options=sample_names,
            key="sample_multiselect",
            help="Selected samples are included with any uploaded files.",
        )
    else:
        st.info("No sample logs in `samples/` yet. Add files there or upload below.")

    uploaded = st.file_uploader(
        "Upload log files",
        accept_multiple_files=True,
        key=f"uploader_{st.session_state.uploader_key}",
    )

    evidence_parts = []
    for name in selected_samples:
        path = SAMPLES_DIR / name
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            evidence_parts.append((name, text))
    if uploaded:
        for f in uploaded:
            text = f.read().decode("utf-8", errors="ignore")
            evidence_parts.append((f.name, text))

    has_evidence = bool(evidence_parts)
    if has_evidence:
        st.markdown("**Evidence summary**")
        for name, text in evidence_parts:
            lines = text.count("\n") + (1 if text.strip() else 0)
            st.write(f"- `{name}` — ~{lines} lines")

    if st.button("Run correlation", disabled=not has_evidence):
        runbook = load_runbook()
        if runbook is None:
            st.error("`ir_runbook.md` not found. Add it to the project root and try again.")
        else:
            combined = "\n\n".join(
                f"===== {name} =====\n{text}" for name, text in evidence_parts
            )
            user_content = (
                f"## Incident-response runbook\n\n{runbook}\n\n"
                f"## Evidence logs\n\n{combined}"
            )
            with st.spinner("Correlating across sources..."):
                report = ask_groq([
                    {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ])
            st.session_state.report = report
            if not report.startswith("⚠️"):
                saved = save_report(report)
                st.session_state.report_path = str(saved)

    if st.session_state.get("report"):
        level = parse_severity(st.session_state.report)
        if level:
            severity_badge(level)
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
    if st.session_state.get("report"):
        st.caption("Active case report is loaded into this chat.")
    else:
        st.caption("No active report yet — run Correlate & Triage for case-specific answers.")

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
