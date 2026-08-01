"""
Self-check for prepass.py against known lab evidence.
Run: python verify_prepass.py
No API key required. Exits non-zero on failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

from prepass import (
    analyze_beaconing,
    analyze_failed_logins,
    analyze_timeline,
    hash_evidence,
    run_prepass,
    run_prepass_on_dir,
)

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
SAMPLES = ROOT / "samples"
failures: list[str] = []


def expect(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


def load_dir(path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for p in sorted(path.iterdir()):
        if p.is_file() and p.suffix.lower() in {".log", ".txt"}:
            files[p.name] = p.read_text(encoding="utf-8", errors="ignore")
    return files


def main() -> int:
    expect(EVIDENCE.is_dir(), f"missing {EVIDENCE}")
    files = load_dir(EVIDENCE)
    expect(bool(files), "evidence/ has no .log/.txt files")

    md = run_prepass(files)
    expect("## Deterministic pre-pass" in md, "missing pre-pass header")
    expect("Evidence SHA-256:" in md, "missing overall hash")

    h1, _ = hash_evidence(files)
    h2, _ = hash_evidence(files)
    expect(h1 == h2, "hash_evidence not stable for identical input")
    expect(h1 in md, "overall hash not present in markdown")

    auth = files.get("auth_events.log", "")
    failed = "\n".join(analyze_failed_logins(auth))
    expect("`185.220.101.47`: 2 failed" in failed, "auth failed-login count != 2")
    expect("LIKELY BRUTE FORCE" not in failed, "2 failures should not flag brute force")

    # Windows-style failed logons in security_events (explicit Status=FAILED lines)
    sec = files.get("security_events_2026-06-12.log", "")
    if sec:
        win = "\n".join(analyze_failed_logins(sec))
        expect("`91.219.236.18`" in win, "Windows Source= failed logons not counted")
        expect("LIKELY BRUTE FORCE" in win, "3+ Windows failures should flag brute force")

    net = files.get("network_traffic.log", "")
    beacon = "\n".join(analyze_beaconing(net))
    expect("10.0.0.37 -> 185.220.101.47:8443" in beacon, "beacon pair missing")
    expect("60 seconds" in beacon, "beacon average interval should be ~60s")

    # Combined ransomware timeline: SUCCESS LOGIN -> .locked dwell = 17m 9s
    combo = {
        "auth_events.log": files["auth_events.log"],
        "file_events.log": files["file_events.log"],
    }
    timeline = "\n".join(analyze_timeline("\n".join(combo.values())))
    expect("Dwell time" in timeline, "dwell section missing")
    expect("17m 9s" in timeline or "(1029s)" in timeline, "dwell should be 17m 9s / 1029s")

    # samples/ firewall should surface C2-ish busiest pair to :8080
    if SAMPLES.is_dir():
        sample_files = load_dir(SAMPLES)
        if sample_files:
            sample_md = run_prepass(sample_files)
            expect(
                "45.137.21.130:8080" in sample_md,
                "samples firewall beacon/pair should include 45.137.21.130:8080",
            )

    # Directory helper matches map helper for evidence/
    dir_md = run_prepass_on_dir(EVIDENCE)
    expect(dir_md == md, "run_prepass_on_dir(evidence) != run_prepass(files)")

    if failures:
        print("verify_prepass: FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("verify_prepass: OK")
    print(f"  evidence files: {len(files)}")
    print(f"  evidence sha256: {h1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
