# Ransomware Incident Response Runbook

Concise runbook aligned to NIST SP 800-61. Check off each step as you complete it. Verify before destructive actions.

---

## 1. Preparation

1. [ ] Confirm IR roles, on-call contacts, and escalation path (security, IT, legal, execs).
2. [ ] Verify offline/immutable backups exist and restore tests are recent.
3. [ ] Document critical assets, admin accounts, and network segmentation maps.
4. [ ] Pre-stage tools: EDR/AV console, firewall access, log sources (`auth`, network, file), forensic imaging.
5. [ ] Keep known-good images, credential-reset procedures, and out-of-band comms ready.
6. [ ] Define ransomware decision criteria (isolate vs. power-off; when to involve law enforcement/insurer).

---

## 2. Detection & Analysis

1. [ ] Triage alerts: mass `.locked`/encrypted renames, ransom notes (`READ_ME*`), failed→success logins, C2 beaconing.
2. [ ] Preserve evidence — copy logs and samples to `evidence/` before remediation; note collection time and source.
3. [ ] Build a timeline from auth, network, and file events; mark key events (successful login, encryption, ransom note).
4. [ ] Identify patient zero, initial access vector, and compromised accounts/hosts.
5. [ ] Scope blast radius: which systems, shares, backups, and identities are affected.
6. [ ] Confirm ransomware indicators (encryption pattern, note text, C2 IPs/domains); do not invent facts.
7. [ ] Classify severity and notify stakeholders per escalation path.

---

## 3. Containment, Eradication & Recovery

### Containment
1. [ ] Isolate affected hosts from the network (prefer disconnect over wipe until evidence is secured).
2. [ ] Block known C2 / attacker IPs and malicious domains at the firewall/DNS.
3. [ ] Disable or reset compromised accounts; revoke active sessions and tokens.
4. [ ] Pause risky automation (backup jobs writing to infected shares, sync tools spreading files).

### Eradication
5. [ ] Remove malware, persistence (services, scheduled tasks, startup items), and attacker tooling.
6. [ ] Patch or close the initial access path (exposed RDP/SSH, phishing mailbox, vulnerable app).
7. [ ] Hunt for remaining footholds across the estate using IOCs from analysis.

### Recovery
8. [ ] Restore systems from known-good backups after confirming backups are clean.
9. [ ] Rebuild from golden images when restore integrity is uncertain.
10. [ ] Re-enable access gradually; monitor for reinfection or renewed beaconing.
11. [ ] Validate critical business functions before declaring recovery complete.

---

## 4. Post-Incident

1. [ ] Write an incident report (timeline, root cause, impact, actions taken) under `reports/`.
2. [ ] Hold a lessons-learned review within two weeks; assign owners and due dates.
3. [ ] Update detections, firewall rules, backup strategy, and this runbook from findings.
4. [ ] Rotate any remaining at-risk credentials and review privileged access.
5. [ ] Confirm legal/regulatory notifications (if required) were completed.
6. [ ] Archive evidence and reports with retention labels; close the incident ticket.
