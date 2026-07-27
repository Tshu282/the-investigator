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

## Skills so far
- Week 1: Thinks like a security analyst (prompt library)
- Week 2: Can triage suspicious emails - check headers (SPF/DKIM/DMARC, Reply-To), flag urgency/secrecy/authority, recommend out-of-band verification
- Week 3: Can audit server logs for failed-login and brute-force patterns (see audit.py)
- Week 4: Can hunt network beaconing (hunt.py) and reconstruct an incident timeline from multiple logs to guide response (timeline.py).
- Week 5: Can auto-triage ransomware evidence with a local LLM (triage.py + ir_runbook.md) — confidence-rated findings, MITRE mapping, and reports written under reports/ when evidence/ changes (GitHub Actions Auto-Triage).
- Week 6: A Streamlit SOC Copilot (`app.py`) that correlates four telemetry sources (firewall, Sysmon, Windows, Suricata) via Groq and returns a triaged report with MITRE mapping, severity, and response plan.
- Week 7: Deployed SOC Copilot (v1.2) with Case Files tab, runbook-aware correlation, and chat that can use a live correlation or a saved case file as the active case.
More coming each week.

## Run locally
```bash
pip install -r requirements.txt
python -m streamlit run app.py
```
