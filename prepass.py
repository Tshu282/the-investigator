"""
Deterministic pre-pass for The Investigator.

Runs rule-based checks (failed logins, beaconing hints, timeline markers)
before any LLM call. Returns facts the model must reconcile — not invent.
Portable over arbitrary uploads / evidence files; week lab scripts stay as-is.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

# Classic lab / auth logs: "FAILED LOGIN ... from <ip>"
FAILED_LOGIN_RE = re.compile(r"FAILED\s+LOGIN", re.IGNORECASE)
FROM_IP_RE = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
# Windows Security-style lines that keep Source= and Status=FAILED on one line
WIN_FAIL_SOURCE_RE = re.compile(
    r"Source=(\d{1,3}(?:\.\d{1,3}){3}).*?Status\s*=\s*FAILED"
    r"|Status\s*=\s*FAILED.*?Source=(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
# e.g. "09:00:05 10.0.0.37 -> 185.220.101.47:8443"
# or "ALLOW TCP 10.1.1.20:50122 -> 203.0.113.10:443"
PAIR_RE = re.compile(
    r"(?:(?P<time>\d{1,2}:\d{2}:\d{2})\s+)?"
    r"(?P<source>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s*->\s*"
    r"(?P<dest>\d{1,3}(?:\.\d{1,3}){3}:\d+)"
)
# "NETWORK 10.0.0.37 established connection to 185.220.101.47:8443"
CONN_TO_RE = re.compile(
    r"(?P<source>\d{1,3}(?:\.\d{1,3}){3})\s+established connection to\s+"
    r"(?P<dest>\d{1,3}(?:\.\d{1,3}){3}:\d+)",
    re.IGNORECASE,
)
FULL_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
KEY_MARKERS = ("SUCCESS LOGIN", ".locked", "READ_ME", "FAILED LOGIN")


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def analyze_failed_logins(text: str) -> list[str]:
    """Count failed-login / failed-logon attempts by source IP; flag 3+ as likely brute force."""
    counts: dict[str, int] = {}
    for line in _lines(text):
        if FAILED_LOGIN_RE.search(line):
            match = FROM_IP_RE.search(line)
            if match:
                ip = match.group(1)
                counts[ip] = counts.get(ip, 0) + 1
                continue
        win = WIN_FAIL_SOURCE_RE.search(line)
        if win:
            ip = win.group(1) or win.group(2)
            if ip:
                counts[ip] = counts.get(ip, 0) + 1

    out = ["### Failed login summary"]
    if not counts:
        out.append("- No failed-login / failed-logon source IPs matched.")
        return out

    for ip, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        flag = " — LIKELY BRUTE FORCE (≥3)" if count >= 3 else ""
        out.append(f"- `{ip}`: {count} failed attempt(s){flag}")
    return out


def analyze_beaconing(text: str) -> list[str]:
    """Find the busiest source→dest:port pair and average interval when times exist."""
    pair_counts: dict[str, int] = {}
    pair_times: dict[str, list[str]] = {}

    for line in _lines(text):
        match = PAIR_RE.search(line)
        if match:
            pair = f"{match.group('source')} -> {match.group('dest')}"
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
            t = match.group("time")
            if t:
                pair_times.setdefault(pair, []).append(t)
            continue
        conn = CONN_TO_RE.search(line)
        if conn:
            pair = f"{conn.group('source')} -> {conn.group('dest')}"
            pair_counts[pair] = pair_counts.get(pair, 0) + 1

    out = ["### Beaconing suspect (busiest pair)"]
    if not pair_counts:
        out.append("- No source→destination:port connection pairs matched.")
        return out

    top_pair = max(pair_counts, key=pair_counts.get)
    top_count = pair_counts[top_pair]
    times = pair_times.get(top_pair, [])
    avg_note = "n/a (need ≥2 timestamps)"
    if len(times) >= 2:
        try:
            stamps = [datetime.strptime(t, "%H:%M:%S") for t in times]
            intervals = [
                (stamps[i + 1] - stamps[i]).total_seconds()
                for i in range(len(stamps) - 1)
            ]
            avg = sum(intervals) / len(intervals)
            avg_note = f"{avg:.0f} seconds"
        except ValueError:
            avg_note = "n/a (unparseable times)"

    sample = ", ".join(times[:8]) + ("…" if len(times) > 8 else "") if times else "n/a"
    out.extend([
        f"- Pair: `{top_pair}`",
        f"- Connections: {top_count}",
        f"- Average seconds between connections: {avg_note}",
        f"- Sample timestamps: {sample}",
    ])
    return out


def _event_timestamp(line: str) -> datetime | None:
    match = FULL_TS_RE.match(line)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    iso = ISO_TS_RE.match(line)
    if iso:
        try:
            return datetime.strptime(iso.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return None


def analyze_timeline(text: str) -> list[str]:
    """Flag key markers and, when possible, dwell from first SUCCESS LOGIN to first .locked."""
    dated: list[tuple[datetime, str]] = []
    for line in _lines(text):
        ts = _event_timestamp(line)
        if ts is not None:
            dated.append((ts, line))

    out = ["### Timeline markers"]
    if not dated:
        out.append("- No `YYYY-MM-DD HH:MM:SS` / ISO timestamps found for timeline merge.")
        return out

    dated.sort(key=lambda item: item[0])
    key_events = [
        line for _, line in dated
        if any(marker in line for marker in KEY_MARKERS)
    ]

    if not key_events:
        out.append(
            "- No SUCCESS LOGIN / .locked / READ_ME / FAILED LOGIN markers in dated lines."
        )
    else:
        for line in key_events[:20]:
            out.append(f"- `{line}`")
        if len(key_events) > 20:
            out.append(f"- … ({len(key_events) - 20} more key events)")

    first_login = next((ts for ts, line in dated if "SUCCESS LOGIN" in line), None)
    first_locked = next((ts for ts, line in dated if ".locked" in line), None)
    if first_login and first_locked and first_locked >= first_login:
        total = int((first_locked - first_login).total_seconds())
        minutes, seconds = divmod(total, 60)
        out.append("### Dwell time")
        out.append(
            f"- From first SUCCESS LOGIN (`{first_login}`) to first `.locked` "
            f"(`{first_locked}`): **{minutes}m {seconds}s** ({total}s)"
        )
    return out


def hash_evidence(files: dict[str, str]) -> tuple[str, list[str]]:
    """Return overall SHA-256 and per-file short hash lines."""
    hasher = hashlib.sha256()
    per_file: list[str] = []
    for name in sorted(files):
        raw = files[name].encode("utf-8", errors="replace")
        hasher.update(name.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(raw)
        per_file.append(f"- `{name}`: `{hashlib.sha256(raw).hexdigest()[:16]}…`")
    return hasher.hexdigest(), per_file


def run_prepass(files: dict[str, str]) -> str:
    """
    Run all deterministic checks on a name→text map.
    Returns Markdown suitable for UI display and LLM injection.
    """
    if not files:
        return "_No files provided for pre-pass._"

    combined = "\n".join(files[name] for name in sorted(files))
    overall, per_file = hash_evidence(files)

    sections: list[str] = [
        "## Deterministic pre-pass",
        "_Rule-based facts (not LLM). The correlation report must reconcile with these._",
        "",
        f"**Files:** {', '.join(f'`{n}`' for n in sorted(files))}",
        f"**Evidence SHA-256:** `{overall}`",
        "",
        "### Per-file hashes (prefix)",
        *per_file,
        "",
        *analyze_failed_logins(combined),
        "",
        *analyze_beaconing(combined),
        "",
        *analyze_timeline(combined),
    ]
    return "\n".join(sections)


def run_prepass_on_dir(directory: str | Path) -> str:
    """Run pre-pass on `.log` / `.txt` files under a directory (e.g. evidence/)."""
    root = Path(directory)
    if not root.is_dir():
        return f"_No directory `{directory}` for pre-pass._"
    files: dict[str, str] = {}
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix.lower() in {".log", ".txt"}:
            files[path.name] = path.read_text(encoding="utf-8", errors="ignore")
    return run_prepass(files)


def case_metadata_footer(
    *,
    model: str,
    file_names: list[str],
    evidence_sha256: str,
    prepass_excerpt: str,
) -> str:
    """Append-only case footer for saved reports."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    excerpt = prepass_excerpt.strip()
    if len(excerpt) > 1200:
        excerpt = excerpt[:1200] + "\n…_(truncated)_"
    names = ", ".join(f"`{n}`" for n in file_names) if file_names else "_(none)_"
    return (
        "\n\n---\n\n"
        "## Case metadata\n"
        f"- Generated: `{stamp}`\n"
        f"- Model: `{model}`\n"
        f"- Evidence files: {names}\n"
        f"- Evidence SHA-256: `{evidence_sha256}`\n"
        f"- Containment: recommendations only — verify before action\n\n"
        "### Pre-pass excerpt\n\n"
        f"{excerpt}\n"
    )


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence")
    print(run_prepass_on_dir(target))
