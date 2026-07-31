# The Investigator

An AI-powered security & network analyst I'm building across 8 weeks.

**Live app:** [https://the-investigator-aj3hchjtbanga5yjc3jodr.streamlit.app/](https://the-investigator-aj3hchjtbanga5yjc3jodr.streamlit.app/)

## What it does
- Correlates uploaded logs (firewall, Sysmon, Windows, Suricata, and more) into one incident verdict via Groq
- Returns a triage report with threat analysis, MITRE ATT&CK mapping, severity, investigation/response plans, and Uncertainties & Flags
- Aligns response steps to `ir_runbook.md`
- Case-aware chat (“Ask the Investigator”) grounded in the active report
- Case Files browser for saved reports under `reports/` — load any file as the active case for chat
- Automated pipeline triage when `evidence/` changes (GitHub Actions + local LLM)
- **Agentic mode:** given a goal, an autonomous loop decides which evidence to read and which MITRE IDs to verify, then returns a cited verdict — observe and recommend only; it does not isolate hosts or block IPs

## Skills so far
- Week 1: Thinks like a security analyst (prompt library)
- Week 2: Can triage suspicious emails - check headers (SPF/DKIM/DMARC, Reply-To), flag urgency/secrecy/authority, recommend out-of-band verification
- Week 3: Can audit server logs for failed-login and brute-force patterns (see audit.py)
- Week 4: Can hunt network beaconing (hunt.py) and reconstruct an incident timeline from multiple logs to guide response (timeline.py).
- Week 5: Can auto-triage ransomware evidence with a local LLM (triage.py + ir_runbook.md) — confidence-rated findings, MITRE mapping, and reports written under reports/ when evidence/ changes (GitHub Actions Auto-Triage).
- Week 6: A Streamlit SOC Copilot (`app.py`) that correlates four telemetry sources (firewall, Sysmon, Windows, Suricata) via Groq and returns a triaged report with MITRE mapping, severity, and response plan.
- Week 7: Deployed SOC Copilot (v1.2) with Case Files tab, runbook-aware correlation, and chat that can use a live correlation or a saved case file as the active case.
- Week 8: Agentic mode (`agent.py` CLI + Autonomous Investigation tab in `app.py`) — tool-calling loop over `evidence/` with `list_evidence`, `read_log`, and `lookup_mitre`; supervisor audits the trail before any containment.

## Agentic mode (Week 8)

The Investigator can run as an **agent**: you give it a goal, and a bounded loop asks the model what to do next. The model may call tools; your code runs them and feeds results back until the model stops and writes a final report (attack chain, hosts/accounts/IPs, MITRE mapping, severity).

| Tool | Purpose |
|------|---------|
| `list_evidence` | List `.log` / `.txt` files under `evidence/` |
| `read_log` | Read one evidence file (sandboxed to that folder) |
| `lookup_mitre` | Resolve a technique ID against a small local MITRE table |

**Interfaces**
- **CLI:** `python agent.py` — colored trail in the terminal via `rich`
- **Streamlit:** Tab 4 — Autonomous Investigation — same loop, trail on the page

**API key (bring your own — never hard-coded)**
- Prefer environment variable: `GROQ_API_KEY`
- Local fallback: `.streamlit/secrets.toml` (gitignored)
- Streamlit Cloud: set `GROQ_API_KEY` in the app’s Secrets

**Human in the loop:** the agent may read and reason. Containment actions (isolate a host, block an IP, disable an account) always need a human; the agent only recommends.

## Run locally
```bash
pip install -r requirements.txt

# Streamlit SOC Copilot (includes Autonomous Investigation)
python -m streamlit run app.py

# CLI agent (uses GROQ_API_KEY, or local .streamlit/secrets.toml)
python agent.py
```
