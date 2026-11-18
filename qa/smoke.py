"""Exercise the CLI, native crypto, and child process boundary without capture privileges."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1]).resolve()

with tempfile.TemporaryDirectory(prefix="nw smoke ") as tmp:
    def run(*args, fail=False, env=None):
        p = subprocess.run([binary, *args], cwd=tmp, env=env, capture_output=True, text=True, timeout=30)
        assert (p.returncode != 0) == fail, (p.stdout, p.stderr)
        return p.stdout

    helper = Path(tmp) / ("test dumpcap.exe" if os.name == "nt" else "test dumpcap")
    subprocess.run(["rustc", "--crate-name", "fixture", root / "qa/capture_fixture.rs", "-o", helper], check=True)
    assert "fixture" in run("interfaces", "--dumpcap", helper)
    rules = root / "rules/default.json"
    flags = ["--iface", "1", "--count", "1000", "--seconds", "2", "--rules", rules, "--dumpcap", helper]
    run("monitor", *flags, "--db", "partial.db", fail=True, env={**os.environ, "NW_FIXTURE_FAIL": "1"})
    with sqlite3.connect(Path(tmp) / "partial.db") as db:
        assert not db.execute("SELECT id FROM runs UNION ALL SELECT id FROM findings").fetchall()
    assert "findings=5" in run("monitor", *flags)
    assert "findings=5" in run("analyze", root / "fixtures/sample_attacks.pcap", "--rules", rules, "--db", "offline.db")
    for dbname in ["offline.db", "nightwatch.db"]:
        text = run("report", "--db", dbname, "--out", "findings report.json")
        data = (Path(tmp) / "findings report.json").read_bytes()
        assert text.split()[0] == "sha256=" + hashlib.sha256(data).hexdigest()
        assert json.loads(data)["finding_count"] == 5
print("PASS: interface listing, failed capture rollback boundary, fixture monitor, offline analysis, exact-byte report digest")
