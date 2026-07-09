import json
import os
import time
from datetime import datetime
from pathlib import Path


REPORT_DIR = Path.home() / ".pegasus_nexus" / "reports"


def generate_html_report(targets, results, args, output_dir=".",
                          cracked_db=None, benchmark=None):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.html"
    path = os.path.join(output_dir, filename)

    successful = [r for r in results if r.get("success")]
    total_targets = len(targets)
    total_attacked = len(results)
    total_cracked = len(successful)
    total_tested = sum(r.get("tested_count", 0) for r in results)
    total_duration = sum(r.get("duration", 0) for r in results)

    cracked_rows = ""
    for r in successful:
        t = r.get("target", {})
        ssid = t.get("ssid", "?")
        bssid = t.get("bssid", "")
        pw = r.get("password", "?")
        dur = r.get("duration", 0)
        tested = r.get("tested_count", 0)
        cracked_rows += f"""
        <tr>
            <td>{ssid}</td>
            <td>{bssid}</td>
            <td class="pw">{pw}</td>
            <td>{dur:.1f}s</td>
            <td>{tested:,}</td>
        </tr>"""

    failed_rows = ""
    for r in results:
        if r.get("success"):
            continue
        t = r.get("target", {})
        ssid = t.get("ssid", "?")
        bssid = t.get("bssid", "")
        dur = r.get("duration", 0)
        tested = r.get("tested_count", 0)
        sig = t.get("signal_strength", -100)
        failed_rows += f"""
        <tr>
            <td>{ssid}</td>
            <td>{bssid}</td>
            <td>{sig} dBm</td>
            <td>{dur:.1f}s</td>
            <td>{tested:,}</td>
        </tr>"""

    cracked_db_section = ""
    if cracked_db:
        entries = "".join(
            f"<tr><td>{b}</td><td class='pw'>{p}</td></tr>"
            for b, p in cracked_db.items()
        )
        cracked_db_section = f"""
        <h2>Credential Database ({len(cracked_db)} entries)</h2>
        <table>
            <tr><th>BSSID</th><th>Password</th></tr>
            {entries}
        </table>"""

    speed_info = ""
    if benchmark:
        speed = benchmark.get("aircrack", {}).get("passwords_per_second", 0)
        if speed:
            speed_info = f"<p>Cracking Speed: {speed:,.0f} p/s</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pegasus-Nexus Report - {ts}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0d1117; color: #c9d1d9; padding: 2rem; }}
h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
h2 {{ color: #58a6ff; margin: 1.5rem 0 0.5rem; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem; margin: 1rem 0; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
         padding: 1.2rem; text-align: center; }}
.card .value {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
.card .label {{ font-size: 0.85rem; color: #8b949e; margin-top: 0.3rem; }}
.card.green .value {{ color: #3fb950; }}
.card.red .value {{ color: #f85149; }}
table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; }}
th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ background: #161b22; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.8rem; }}
tr:hover {{ background: #1c2128; }}
.pw {{ font-family: 'Courier New', monospace; color: #3fb950; }}
.meta {{ color: #8b949e; font-size: 0.9rem; margin: 0.5rem 0; }}
</style>
</head>
<body>
<h1>Pegasus-Nexus Attack Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="summary">
    <div class="card"><div class="value">{total_targets}</div><div class="label">Targets Found</div></div>
    <div class="card"><div class="value">{total_attacked}</div><div class="label">Targets Attacked</div></div>
    <div class="card green"><div class="value">{total_cracked}</div><div class="label">Compromised</div></div>
    <div class="card"><div class="value">{total_tested:,}</div><div class="label">Passwords Tested</div></div>
    <div class="card"><div class="value">{total_duration:.0f}s</div><div class="label">Total Duration</div></div>
</div>

{speed_info}

<h2>Compromised Networks ({total_cracked})</h2>
<table>
    <tr><th>SSID</th><th>BSSID</th><th>Password</th><th>Time</th><th>Tests</th></tr>
    {cracked_rows if cracked_rows else '<tr><td colspan="5">No networks compromised</td></tr>'}
</table>

<h2>Failed Attacks ({total_attacked - total_cracked})</h2>
<table>
    <tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Duration</th><th>Tests</th></tr>
    {failed_rows if failed_rows else '<tr><td colspan="5">No failed attacks</td></tr>'}
</table>

{cracked_db_section}

<p class="meta" style="margin-top:2rem;">Pegasus-Nexus v1.0</p>
</body>
</html>"""

    try:
        with open(path, "w") as f:
            f.write(html)
        print(f"   Report saved: {path}")
        return path
    except OSError as e:
        print(f"   Failed to write report: {e}")
        return None


def generate_json_report(targets, results, args, output_dir=".",
                          cracked_db=None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.json"
    path = os.path.join(output_dir, filename)

    successful = [r for r in results if r.get("success")]
    report = {
        "timestamp": datetime.now().isoformat(),
        "interface": getattr(args, "interface", "?"),
        "mode": "batch" if getattr(args, "batch", False) else "interactive",
        "targets_total": len(targets),
        "targets_attacked": len(results),
        "targets_compromised": len(successful),
        "results": results,
        "cracked_database": cracked_db or {},
    }

    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"   JSON report: {path}")
        return path
    except OSError as e:
        print(f"   Failed to write report: {e}")
        return None
