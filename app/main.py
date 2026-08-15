from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

VERSION = "1.6.1"
app = FastAPI(title="Kingdom Manager", version=VERSION)

DOCKER = os.getenv("DOCKER_HOST", "tcp://docker-socket-proxy:2375").replace("tcp://", "http://")
DATA_DIR = Path(os.getenv("KM_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "kingdom.db"
API_TOKEN = os.getenv("KM_API_TOKEN", "")
TZ = ZoneInfo(os.getenv("TZ", "America/New_York"))
QUARANTINE_NETWORK = os.getenv("KM_QUARANTINE_NETWORK", "kingdom-quarantine")
TRIVY_RUNNER = os.getenv("TRIVY_RUNNER", "kingdom-manager-trivy")
CHECK_SECONDS = int(os.getenv("KM_CHECK_SECONDS", "300"))
IDLE_CPU = float(os.getenv("KM_IDLE_CPU_PERCENT", "3.0"))
IDLE_MINUTES = int(os.getenv("KM_IDLE_MINUTES", "20"))
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
N8N_WEBHOOK = os.getenv("N8N_WEBHOOK_URL", "")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CROWDSEC_URL = os.getenv("CROWDSEC_URL", "")
CROWDSEC_API_KEY = os.getenv("CROWDSEC_API_KEY", "")
FALCO_WEBHOOK_SECRET = os.getenv("FALCO_WEBHOOK_SECRET", "")
DECISION_WINDOW_SECONDS = int(os.getenv("KM_DECISION_WINDOW_SECONDS", "900"))
DECISION_DEBOUNCE_SECONDS = int(os.getenv("KM_DECISION_DEBOUNCE_SECONDS", "120"))
TRIVY_CONTEXT_SECONDS = int(os.getenv("KM_TRIVY_CONTEXT_SECONDS", "604800"))
FALCO_HOST = os.getenv("FALCO_HOST", "falco")
FALCO_HEALTH_PORT = int(os.getenv("FALCO_HEALTH_PORT", "8765"))
TRIVY_AUTO_SCAN_ENABLED = os.getenv("TRIVY_AUTO_SCAN_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
TRIVY_AUTO_SCAN_EVERY_SECONDS = int(os.getenv("TRIVY_AUTO_SCAN_EVERY_SECONDS", "1800"))
TRIVY_AUTO_SCAN_START_DELAY_SECONDS = int(os.getenv("TRIVY_AUTO_SCAN_START_DELAY_SECONDS", "45"))
TRIVY_RESCAN_SECONDS = int(os.getenv("TRIVY_RESCAN_SECONDS", "604800"))
RECOVERY_DOCKER = os.getenv("RECOVERY_DOCKER_HOST", "tcp://recovery-socket-proxy:2375").replace("tcp://", "http://")
RECOVERY_APPROVAL_TTL = int(os.getenv("KM_RECOVERY_APPROVAL_TTL_SECONDS", "900"))

DATA_DIR.mkdir(parents=True, exist_ok=True)


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          kind TEXT NOT NULL, subject TEXT, detail TEXT, severity TEXT DEFAULT 'info'
        );
        CREATE TABLE IF NOT EXISTS policies(
          container_name TEXT PRIMARY KEY,
          auto_restart INTEGER NOT NULL DEFAULT 1,
          auto_update INTEGER NOT NULL DEFAULT 0,
          auto_isolate INTEGER NOT NULL DEFAULT 0,
          allow_rebuild INTEGER NOT NULL DEFAULT 0,
          protected INTEGER NOT NULL DEFAULT 0,
          idle_cpu REAL NOT NULL DEFAULT 3.0,
          idle_minutes INTEGER NOT NULL DEFAULT 20
        );
        CREATE TABLE IF NOT EXISTS runtime_samples(
          container_name TEXT PRIMARY KEY, ts INTEGER NOT NULL,
          cpu REAL NOT NULL DEFAULT 0, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
          idle_since INTEGER
        );
        CREATE TABLE IF NOT EXISTS snapshots(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          container_name TEXT NOT NULL, reason TEXT NOT NULL, inspect_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          source TEXT NOT NULL, severity TEXT NOT NULL, container_name TEXT,
          message TEXT NOT NULL, raw_json TEXT
        );
        CREATE TABLE IF NOT EXISTS decisions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          container_name TEXT, decision TEXT NOT NULL, reason TEXT NOT NULL,
          executed INTEGER NOT NULL DEFAULT 0, result TEXT
        );
        CREATE TABLE IF NOT EXISTS correlation_runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          container_name TEXT, score INTEGER NOT NULL, risk TEXT NOT NULL,
          sources_json TEXT NOT NULL, signals_json TEXT NOT NULL,
          action TEXT NOT NULL, executed INTEGER NOT NULL DEFAULT 0, result TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_security_events_subject_ts
          ON security_events(container_name, ts);
        CREATE INDEX IF NOT EXISTS idx_correlation_subject_ts
          ON correlation_runs(container_name, ts);
        CREATE TABLE IF NOT EXISTS scans(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          container_name TEXT, image TEXT NOT NULL, status TEXT NOT NULL,
          critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
          result_json TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_findings(
          id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
          container_name TEXT, image TEXT NOT NULL, target TEXT, vuln_id TEXT,
          pkg_name TEXT, installed_version TEXT, fixed_version TEXT, severity TEXT, title TEXT,
          FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS risk_profiles(
          container_name TEXT PRIMARY KEY, profile TEXT NOT NULL DEFAULT 'user-app', weight REAL NOT NULL DEFAULT 1.0
        );
        CREATE TABLE IF NOT EXISTS suppressions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, enabled INTEGER NOT NULL DEFAULT 1,
          source TEXT NOT NULL, container_name TEXT, rule_contains TEXT, reason TEXT,
          UNIQUE(source,container_name,rule_contains)
        );
        CREATE TABLE IF NOT EXISTS incidents(
          id INTEGER PRIMARY KEY AUTOINCREMENT, created_ts INTEGER NOT NULL, updated_ts INTEGER NOT NULL,
          container_name TEXT, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
          title TEXT NOT NULL, summary TEXT, score INTEGER NOT NULL DEFAULT 0,
          sources_json TEXT NOT NULL DEFAULT '[]', correlation_id INTEGER, resolution TEXT
        );
        CREATE TABLE IF NOT EXISTS incident_evidence(
          id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, ts INTEGER NOT NULL,
          evidence_type TEXT NOT NULL, label TEXT NOT NULL, payload TEXT NOT NULL,
          FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS recovery_plans(
          id INTEGER PRIMARY KEY AUTOINCREMENT, created_ts INTEGER NOT NULL, expires_ts INTEGER NOT NULL,
          container_name TEXT NOT NULL, incident_id INTEGER, action TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          snapshot_id INTEGER, plan_json TEXT NOT NULL, approved_ts INTEGER, executed_ts INTEGER, result TEXT
        );
        CREATE TABLE IF NOT EXISTS maintenance(
          container_name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, until_ts INTEGER, reason TEXT
        );
        """)


init_db()


def now() -> int:
    return int(time.time())


def event(kind: str, subject: str = "", detail: Any = "", severity: str = "info") -> None:
    if not isinstance(detail, str):
        detail = json.dumps(detail, separators=(",", ":"), default=str)
    with conn() as c:
        c.execute("INSERT INTO events(ts,kind,subject,detail,severity) VALUES(?,?,?,?,?)",
                  (now(), kind, subject, detail[:20000], severity))


def rowdicts(rows):
    return [dict(r) for r in rows]


def require_token(authorization: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(503, "KM_API_TOKEN is not configured")
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(401, "Invalid Kingdom Manager token")


async def docker(method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.request(method, DOCKER + path, **kwargs)
        return r


async def docker_json(method: str, path: str, ok=(200,), **kwargs):
    r = await docker(method, path, **kwargs)
    if r.status_code not in ok:
        raise HTTPException(r.status_code, r.text[:2000])
    return r.json() if r.content else None


async def inspect_container(name: str) -> dict:
    return await docker_json("GET", f"/containers/{quote(name, safe='')}/json")


async def list_containers(all_: bool = True) -> list[dict]:
    data = await docker_json("GET", f"/containers/json?all={1 if all_ else 0}")
    out = []
    for c in data:
        out.append({
            "id": c.get("Id", "")[:12], "full_id": c.get("Id", ""),
            "name": (c.get("Names") or [""])[0].lstrip("/"),
            "image": c.get("Image", ""), "image_id": c.get("ImageID", ""),
            "state": c.get("State", "unknown"), "status": c.get("Status", ""),
            "labels": c.get("Labels") or {},
        })
    return out


def default_policy(name: str) -> dict:
    with conn() as c:
        r = c.execute("SELECT * FROM policies WHERE container_name=?", (name,)).fetchone()
        if not r:
            c.execute("INSERT INTO policies(container_name,idle_cpu,idle_minutes) VALUES(?,?,?)",
                      (name, IDLE_CPU, IDLE_MINUTES))
            r = c.execute("SELECT * FROM policies WHERE container_name=?", (name,)).fetchone()
    return dict(r)


async def sample_stats(name: str) -> dict:
    r = await docker("GET", f"/containers/{quote(name, safe='')}/stats?stream=false&one-shot=true")
    if r.status_code != 200:
        return {"cpu": 0.0, "rx": 0, "tx": 0}
    s = r.json()
    cpu_stats, pre = s.get("cpu_stats", {}), s.get("precpu_stats", {})
    total = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    system = cpu_stats.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    cpus = cpu_stats.get("online_cpus") or len(cpu_stats.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    cpu = (total / system * cpus * 100.0) if total > 0 and system > 0 else 0.0
    rx = tx = 0
    for n in (s.get("networks") or {}).values():
        rx += int(n.get("rx_bytes", 0)); tx += int(n.get("tx_bytes", 0))
    return {"cpu": round(cpu, 2), "rx": rx, "tx": tx}


def update_idle(name: str, stats: dict, policy: dict) -> tuple[bool, int | None]:
    t = now()
    with conn() as c:
        old = c.execute("SELECT * FROM runtime_samples WHERE container_name=?", (name,)).fetchone()
        network_quiet = True
        if old:
            network_quiet = (stats["rx"] - old["rx"] < 1024 * 256 and stats["tx"] - old["tx"] < 1024 * 256)
        low = stats["cpu"] <= float(policy["idle_cpu"]) and network_quiet
        idle_since = (old["idle_since"] if old and old["idle_since"] else t) if low else None
        c.execute("""INSERT INTO runtime_samples(container_name,ts,cpu,rx,tx,idle_since) VALUES(?,?,?,?,?,?)
          ON CONFLICT(container_name) DO UPDATE SET ts=excluded.ts,cpu=excluded.cpu,rx=excluded.rx,tx=excluded.tx,idle_since=excluded.idle_since""",
                  (name, t, stats["cpu"], stats["rx"], stats["tx"], idle_since))
    idle = bool(idle_since and t - idle_since >= int(policy["idle_minutes"]) * 60)
    return idle, idle_since


async def snapshot(name: str, reason: str) -> int:
    obj = await inspect_container(name)
    with conn() as c:
        cur = c.execute("INSERT INTO snapshots(ts,container_name,reason,inspect_json) VALUES(?,?,?,?)",
                        (now(), name, reason, json.dumps(obj, default=str)))
        sid = cur.lastrowid
    event("snapshot", name, {"id": sid, "reason": reason})
    return sid


async def notify(title: str, body: str, severity: str = "info") -> None:
    payload = {"title": title, "body": body, "severity": severity, "ts": now()}
    async with httpx.AsyncClient(timeout=10) as client:
        if DISCORD_WEBHOOK:
            try:
                await client.post(DISCORD_WEBHOOK, json={"content": f"👑 **{title}**\n{body}"})
            except Exception as e:
                event("notify_error", "discord", str(e), "warning")
        if N8N_WEBHOOK:
            try:
                await client.post(N8N_WEBHOOK, json=payload)
            except Exception as e:
                event("notify_error", "n8n", str(e), "warning")


async def ensure_quarantine_network() -> None:
    r = await docker("GET", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}")
    if r.status_code == 200:
        return
    r = await docker("POST", "/networks/create", json={"Name": QUARANTINE_NETWORK, "Internal": True, "CheckDuplicate": True})
    if r.status_code not in (201, 409):
        raise HTTPException(r.status_code, r.text)


async def isolate(name: str) -> dict:
    policy = default_policy(name)
    if policy["protected"]:
        raise HTTPException(409, "Protected container cannot be isolated automatically")
    await snapshot(name, "pre-isolation")
    obj = await inspect_container(name)
    await ensure_quarantine_network()
    original = list((obj.get("NetworkSettings", {}).get("Networks") or {}).keys())
    r = await docker("POST", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}/connect", json={"Container": name})
    if r.status_code not in (200, 201, 403):
        raise HTTPException(r.status_code, r.text)
    disconnected = []
    for net in original:
        if net == QUARANTINE_NETWORK:
            continue
        rr = await docker("POST", f"/networks/{quote(net, safe='')}/disconnect", json={"Container": name, "Force": True})
        if rr.status_code in (200, 201):
            disconnected.append(net)
    event("security", name, {"action": "isolated", "from": disconnected}, "critical")
    await notify("Container isolated", f"{name} was moved to {QUARANTINE_NETWORK}. Original networks: {', '.join(disconnected)}", "critical")
    return {"ok": True, "isolated": name, "disconnected": disconnected}


async def restore_networks_from_snapshot(name: str) -> dict:
    with conn() as c:
        r = c.execute("SELECT * FROM snapshots WHERE container_name=? AND reason='pre-isolation' ORDER BY id DESC LIMIT 1", (name,)).fetchone()
    if not r:
        raise HTTPException(404, "No pre-isolation snapshot")
    obj = json.loads(r["inspect_json"])
    networks = list((obj.get("NetworkSettings", {}).get("Networks") or {}).keys())
    restored = []
    for net in networks:
        rr = await docker("POST", f"/networks/{quote(net, safe='')}/connect", json={"Container": name})
        if rr.status_code in (200, 201, 403):
            restored.append(net)
    await docker("POST", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}/disconnect", json={"Container": name, "Force": True})
    event("recovery", name, {"action": "networks_restored", "networks": restored})
    return {"ok": True, "restored": restored}


async def trivy_exec(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    """Run Trivy inside the dedicated runner through Docker exec."""
    create = await docker_json("POST", f"/containers/{quote(TRIVY_RUNNER, safe='')}/exec", ok=(201,), json={
        "AttachStdout": True, "AttachStderr": True, "Cmd": cmd
    })
    exid = create["Id"]
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(DOCKER + f"/exec/{exid}/start", json={"Detach": False, "Tty": False})
    raw = r.content.decode("utf-8", errors="ignore")
    # Docker's non-TTY exec stream may contain 8-byte multiplexing frame headers.
    # Trivy JSON starts at the first '{'.
    p = raw.find("{")
    if p >= 0:
        raw = raw[p:]
    inspect = await docker("GET", f"/exec/{exid}/json")
    exit_code = inspect.json().get("ExitCode", 1) if inspect.status_code == 200 else (0 if r.status_code == 200 else 1)
    return int(exit_code or 0), raw


async def trivy_scan(name: str) -> dict:
    obj = await inspect_container(name)
    image = obj.get("Config", {}).get("Image") or ""
    if not image:
        raise HTTPException(400, "Container has no image reference")

    # Prefer the local Docker image exposed through the dedicated read-only socket proxy;
    # fall back to the registry for images that are not present locally.
    cmd = [
        "trivy", "image", "--quiet", "--format", "json",
        "--scanners", "vuln", "--image-src", "docker,remote",
        "--timeout", "10m", image,
    ]
    exit_code, raw = await trivy_exec(cmd, timeout=720)
    status = "ok" if exit_code == 0 else "error"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    result: Any = {"raw": raw[-20000:]}
    findings: list[dict] = []
    try:
        result = json.loads(raw)
        for section in result.get("Results") or []:
            target = str(section.get("Target") or "")
            for v in section.get("Vulnerabilities") or []:
                sev = str(v.get("Severity") or "UNKNOWN").lower()
                if sev in counts:
                    counts[sev] += 1
                findings.append({
                    "target": target,
                    "vuln_id": str(v.get("VulnerabilityID") or ""),
                    "pkg_name": str(v.get("PkgName") or ""),
                    "installed_version": str(v.get("InstalledVersion") or ""),
                    "fixed_version": str(v.get("FixedVersion") or ""),
                    "severity": sev,
                    "title": str(v.get("Title") or v.get("Description") or "")[:1000],
                })
    except Exception as e:
        status = "error"
        result = {"error": str(e), "raw": raw[-20000:]}

    with conn() as c:
        cur = c.execute(
            "INSERT INTO scans(ts,container_name,image,status,critical,high,medium,result_json) VALUES(?,?,?,?,?,?,?,?)",
            (now(), name, image, status, counts["critical"], counts["high"], counts["medium"], json.dumps(result, default=str)[:1000000])
        )
        scan_id = cur.lastrowid
        if status == "ok":
            c.executemany(
                "INSERT INTO scan_findings(scan_id,container_name,image,target,vuln_id,pkg_name,installed_version,fixed_version,severity,title) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, name, image, f["target"], f["vuln_id"], f["pkg_name"], f["installed_version"], f["fixed_version"], f["severity"], f["title"]) for f in findings]
            )

    sev = "critical" if counts["critical"] else ("high" if counts["high"] else "info")
    event("trivy", name, {"image": image, **counts, "status": status, "scan_id": scan_id}, sev)

    decision = None
    if status == "ok" and (counts["critical"] or counts["high"]):
        # Feed the scan into the same correlation engine used by runtime detections.
        # Trivy is contextual exposure evidence and can never isolate by itself.
        trigger_sev = "critical" if counts["critical"] else "high"
        decision = await correlate_security(
            name, "trivy", trigger_sev,
            f"{counts['critical']} critical and {counts['high']} high vulnerabilities in {image}"
        )
        if counts["critical"]:
            await notify("Critical image vulnerabilities", f"{name} ({image}) has {counts['critical']} critical and {counts['high']} high findings. No isolation occurs from Trivy alone.", "critical")

    top = [f for f in findings if f["severity"] in {"critical", "high"}][:20]
    return {"scan_id": scan_id, "container": name, "image": image, "status": status, **counts,
            "total": len(findings), "top_findings": top, "decision": decision}


async def pull_image(image: str) -> dict:
    # Works for public registries. Private registry auth can be added later without storing credentials in the DB.
    before = None
    r0 = await docker("GET", f"/images/{quote(image, safe='')}/json")
    if r0.status_code == 200:
        before = r0.json().get("Id")
    r = await docker("POST", f"/images/create?fromImage={quote(image, safe='')}")
    if r.status_code not in (200, 201):
        raise HTTPException(r.status_code, r.text[-2000:])
    r1 = await docker("GET", f"/images/{quote(image, safe='')}/json")
    after = r1.json().get("Id") if r1.status_code == 200 else None
    return {"image": image, "before": before, "after": after, "update_available": bool(before and after and before != after)}


def inferred_profile(name: str) -> tuple[str, float]:
    n=(name or '').lower()
    if any(x in n for x in ('cowrie','opencanary','honeypot')): return ('honeypot', 0.4)
    if any(x in n for x in ('kingdom-manager','proxy-manager','portainer','vaultwarden')): return ('critical-infrastructure', 1.5)
    if any(x in n for x in ('postgres','mysql','mariadb','redis','database','_db','-db')): return ('database', 1.3)
    if any(x in n for x in ('falco','clamav','crowdsec','trivy')): return ('security', 1.2)
    return ('user-app', 1.0)


def risk_profile(name: str) -> dict:
    with conn() as c:
        r=c.execute('SELECT profile,weight FROM risk_profiles WHERE container_name=?',(name,)).fetchone()
        if r: return dict(r)
    profile,weight=inferred_profile(name)
    return {'profile':profile,'weight':weight}


def falco_rule_from_message(message: str) -> str:
    m=(message or '').lower()
    if 'sensitive file opened' in m or '/etc/shadow' in m: return 'Read sensitive file untrusted'
    if 'executing binary not part of base image' in m: return 'Executing binary not part of base image'
    if 'redirect stdout/stdin' in m: return 'Redirect STDOUT/STDIN to Network Connection in Container'
    return ''


def is_suppressed(source: str, name: str | None, message: str) -> tuple[bool,str]:
    rule=falco_rule_from_message(message) if source.lower()=='falco' else ''
    with conn() as c:
        rows=c.execute('SELECT container_name,rule_contains,reason FROM suppressions WHERE enabled=1 AND source=?',(source.lower(),)).fetchall()
    for r in rows:
        if r['container_name'] and r['container_name'] != (name or ''): continue
        if r['rule_contains'] and r['rule_contains'].lower() not in (rule+' '+message).lower(): continue
        return True, (r['reason'] or 'known-good suppression')
    return False,''


async def correlate_security(name: str | None, trigger_source: str, trigger_severity: str, trigger_message: str) -> dict:
    """Correlate independent security engines before allowing an automated response.

    Repeated events from one engine do not multiply risk. For each source we keep
    only the strongest recent signal. Trivy is contextual vulnerability evidence,
    not proof of compromise, so it can raise risk/recommend an update but cannot
    by itself cause isolation.
    """
    subject = name or "host"
    t = now()
    suppressed, suppression_reason = is_suppressed(trigger_source, name, trigger_message)
    if suppressed:
        with conn() as c:
            c.execute("INSERT INTO correlation_runs(ts,container_name,score,risk,sources_json,signals_json,action,executed,result) VALUES(?,?,?,?,?,?,?,?,?)",
                      (t,name,0,"low",json.dumps([trigger_source]),json.dumps([{"source":trigger_source,"suppressed":True,"reason":suppression_reason}]),"suppressed",0,suppression_reason))
        return {"risk":"low","score":0,"action":"suppressed","executed":False,"reason":suppression_reason,"sources":[trigger_source]}
    severity_weight = {"critical": 45, "high": 25, "warning": 20, "medium": 12, "info": 5, "notice": 5, "low": 3}
    source_bonus = {"clamav": 20, "falco": 0, "crowdsec": 10, "trivy": 0}
    strongest: dict[str, dict] = {}

    with conn() as c:
        rows = c.execute(
            "SELECT source,severity,message,ts FROM security_events WHERE coalesce(container_name,'host')=? AND ts>? ORDER BY ts DESC",
            (subject, t - DECISION_WINDOW_SECONDS)
        ).fetchall()
        for r in rows:
            src = str(r["source"]).lower()
            sev = str(r["severity"]).lower()
            weight = severity_weight.get(sev, 5) + source_bonus.get(src, 0)
            old = strongest.get(src)
            if old is None or weight > old["weight"]:
                strongest[src] = {"source": src, "severity": sev, "message": r["message"], "ts": r["ts"], "weight": weight}

        # Latest Trivy scan contributes exposure context for a container, but never counts as active compromise.
        if name:
            scan = c.execute(
                "SELECT ts,critical,high,medium,image FROM scans WHERE container_name=? AND status='ok' AND ts>? ORDER BY id DESC LIMIT 1",
                (name, t - TRIVY_CONTEXT_SECONDS)
            ).fetchone()
            if scan and (scan["critical"] or scan["high"]):
                w = 25 if scan["critical"] else 12
                strongest["trivy"] = {
                    "source":"trivy", "severity":"critical" if scan["critical"] else "high",
                    "message":f"{scan['critical']} critical / {scan['high']} high CVEs in {scan['image']}",
                    "ts":scan["ts"], "weight":w
                }

    active_sources = {k:v for k,v in strongest.items() if k != "trivy"}
    score = sum(v["weight"] for v in strongest.values())
    source_count = len(active_sources)
    malware = any(k == "clamav" and (v["severity"] in {"critical","high"} or "infect" in v["message"].lower() or "malware" in v["message"].lower()) for k,v in strongest.items())
    falco_critical = strongest.get("falco", {}).get("severity") == "critical"
    crowdsec_signal = "crowdsec" in active_sources
    vulnerable = "trivy" in strongest

    if score >= 90 and source_count >= 2:
        risk, action = "critical", "recommend_isolation"
    elif malware and source_count >= 2:
        risk, action = "critical", "recommend_isolation"
    elif score >= 60 or (falco_critical and vulnerable) or (falco_critical and crowdsec_signal):
        risk, action = "high", "investigate"
    elif malware:
        risk, action = "high", "quarantine_evidence"
    elif vulnerable and source_count == 0:
        risk, action = "medium", "recommend_update"
    elif score >= 30:
        risk, action = "medium", "investigate"
    else:
        risk, action = "low", "record"

    execute = False
    result: Any = None
    policy = default_policy(name) if name else None
    if action == "recommend_isolation" and name and policy and policy["auto_isolate"] and not policy["protected"]:
        action = "isolate"
        execute = True

    signals = list(strongest.values())
    sources = sorted(strongest.keys())
    reason = f"correlated risk={risk} score={score} sources={','.join(sources) or trigger_source}: {trigger_message}"

    # Debounce identical decisions for the same subject. Events are still retained.
    with conn() as c:
        previous = c.execute(
            "SELECT id,ts,action,score,risk FROM correlation_runs WHERE coalesce(container_name,'host')=? ORDER BY id DESC LIMIT 1",
            (subject,)
        ).fetchone()
        if previous and previous["action"] == action and t - int(previous["ts"]) < DECISION_DEBOUNCE_SECONDS:
            return {"id": previous["id"], "decision": action, "risk": risk, "score": score, "sources": sources, "executed": False, "debounced": True}

        cur = c.execute(
            "INSERT INTO correlation_runs(ts,container_name,score,risk,sources_json,signals_json,action,executed) VALUES(?,?,?,?,?,?,?,?)",
            (t, name, score, risk, json.dumps(sources), json.dumps(signals, default=str), action, int(execute))
        )
        correlation_id = cur.lastrowid
        dcur = c.execute("INSERT INTO decisions(ts,container_name,decision,reason,executed) VALUES(?,?,?,?,?)",
                         (t, name, action, reason, int(execute)))
        decision_id = dcur.lastrowid

    if execute and name:
        try:
            result = await isolate(name)
        except Exception as e:
            result = {"error": str(e)}
            with conn() as c:
                c.execute("UPDATE correlation_runs SET result=? WHERE id=?", (json.dumps(result), correlation_id))
                c.execute("UPDATE decisions SET result=? WHERE id=?", (json.dumps(result), decision_id))
    if risk in {"high", "critical"}:
        await notify(
            f"Kingdom {risk.upper()} risk",
            f"{subject} — score {score} from {', '.join(sources)}\nDecision: {action}\nTrigger: {trigger_message}",
            risk
        )
    return {"id": decision_id, "correlation_id": correlation_id, "decision": action, "risk": risk, "score": score, "sources": sources, "signals": signals, "executed": execute, "result": result}


def maintenance_active(name: str | None) -> bool:
    if not name: return False
    with conn() as c:
        r=c.execute("SELECT enabled,until_ts FROM maintenance WHERE container_name=?",(name,)).fetchone()
    return bool(r and r["enabled"] and (not r["until_ts"] or int(r["until_ts"])>now()))

def upsert_incident(name: str | None, decision: dict, trigger_source: str, message: str) -> int | None:
    risk=str(decision.get("risk","low")); score=int(decision.get("score",0) or 0)
    if risk not in {"medium","high","critical"}: return None
    subject=name or "host"; t=now(); sources=decision.get("sources") or [trigger_source]
    with conn() as c:
        r=c.execute("SELECT id,sources_json FROM incidents WHERE coalesce(container_name,'host')=? AND status IN ('open','investigating','isolated') ORDER BY id DESC LIMIT 1",(subject,)).fetchone()
        if r:
            merged=sorted(set(json.loads(r["sources_json"] or '[]')+list(sources)))
            c.execute("UPDATE incidents SET updated_ts=?,severity=?,score=?,sources_json=?,summary=? WHERE id=?",(t,risk,score,json.dumps(merged),message[:1000],r["id"]))
            iid=int(r["id"])
        else:
            cur=c.execute("INSERT INTO incidents(created_ts,updated_ts,container_name,severity,status,title,summary,score,sources_json,correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?)",(t,t,name,risk,'open',f'{risk.upper()} security incident — {subject}',message[:1000],score,json.dumps(sources),decision.get('correlation_id')))
            iid=int(cur.lastrowid)
        c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(iid,t,'signal',trigger_source,json.dumps({'message':message,'decision':decision},default=str)[:100000]))
    return iid

async def decision_for_security(source: str, severity: str, name: str | None, message: str) -> dict:
    if maintenance_active(name):
        event('maintenance_signal',name or 'host',{'source':source,'message':message},severity)
        return {'risk':'low','score':0,'action':'maintenance-record','executed':False,'sources':[source],'maintenance':True}
    d=await correlate_security(name, source.lower(), severity.lower(), message)
    iid=upsert_incident(name,d,source,message)
    if iid: d['incident_id']=iid
    return d


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
async def health():
    r = await docker("GET", "/_ping")
    return {"ok": r.status_code == 200, "version": VERSION, "docker": r.text.strip() if r.status_code == 200 else "down"}


@app.get("/api/overview")
async def overview(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cs = await list_containers()
    running = sum(c["state"] == "running" for c in cs)
    with conn() as c:
        sec24 = c.execute("SELECT count(*) FROM security_events WHERE ts>?", (now()-86400,)).fetchone()[0]
        dec24 = c.execute("SELECT count(*) FROM decisions WHERE ts>?", (now()-86400,)).fetchone()[0]
        scans = c.execute("SELECT count(*) FROM scans").fetchone()[0]
    return {"containers": len(cs), "running": running, "stopped": len(cs)-running,
            "security_24h": sec24, "decisions_24h": dec24, "scans": scans, "version": VERSION}


@app.get("/api/containers")
async def api_containers(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cs = await list_containers()
    for c in cs:
        c["policy"] = default_policy(c["name"])
        with conn() as db:
            s = db.execute("SELECT cpu,idle_since,ts FROM runtime_samples WHERE container_name=?", (c["name"],)).fetchone()
        c["runtime"] = dict(s) if s else None
    return cs


@app.post("/api/containers/{name}/{action}")
async def container_action(name: str, action: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    if action not in {"start", "stop", "restart", "pause", "unpause"}:
        raise HTTPException(400, "Unsupported action")
    p = default_policy(name)
    if p["protected"] and action in {"stop", "pause"}:
        raise HTTPException(409, "Container is protected by Kingdom policy")
    if action in {"stop", "restart", "pause"}:
        await snapshot(name, f"pre-{action}")
    r = await docker("POST", f"/containers/{quote(name, safe='')}/{action}")
    if r.status_code not in (204, 304):
        raise HTTPException(r.status_code, r.text[:2000])
    event("container", name, action)
    return {"ok": True, "container": name, "action": action}


@app.post("/api/containers/{name}/sample")
async def manual_sample(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    p = default_policy(name)
    s = await sample_stats(name)
    idle, idle_since = update_idle(name, s, p)
    return {**s, "idle": idle, "idle_since": idle_since}


@app.put("/api/policies/{name}")
async def set_policy(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization)
    data = await request.json()
    allowed = {"auto_restart", "auto_update", "auto_isolate", "allow_rebuild", "protected", "idle_cpu", "idle_minutes"}
    current = default_policy(name)
    for k, v in data.items():
        if k in allowed:
            current[k] = v
    with conn() as c:
        c.execute("""UPDATE policies SET auto_restart=?,auto_update=?,auto_isolate=?,allow_rebuild=?,protected=?,idle_cpu=?,idle_minutes=? WHERE container_name=?""",
                  (int(bool(current["auto_restart"])), int(bool(current["auto_update"])), int(bool(current["auto_isolate"])),
                   int(bool(current["allow_rebuild"])), int(bool(current["protected"])), float(current["idle_cpu"]), int(current["idle_minutes"]), name))
    event("policy", name, data)
    return default_policy(name)


@app.post("/api/security/event")
async def security_event(request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization)
    data = await request.json()
    source = str(data.get("source", "unknown"))
    severity = str(data.get("severity", "info")).lower()
    name = data.get("container") or data.get("container_name")
    message = str(data.get("message", "security event"))
    with conn() as c:
        c.execute("INSERT INTO security_events(ts,source,severity,container_name,message,raw_json) VALUES(?,?,?,?,?,?)",
                  (now(), source, severity, name, message, json.dumps(data, default=str)[:100000]))
    event("security_event", name or "host", {"source": source, "message": message}, severity)
    decision = await decision_for_security(source, severity, name, message)
    return {"ok": True, "decision": decision}


@app.post("/api/security/falco")
async def falco_webhook(request: Request, token: str = ""):
    # Falco posts here directly over the private security network.
    # A shared token prevents the same route being abused through the web proxy.
    if FALCO_WEBHOOK_SECRET and token != FALCO_WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid Falco webhook token")
    data = await request.json()
    severity = str(data.get("priority", "warning")).lower()
    if severity in {"emergency", "alert", "critical"}: severity = "critical"
    elif severity in {"error", "warning"}: severity = "high"
    else: severity = "info"
    output_fields = data.get("output_fields") or {}
    name = output_fields.get("container.name") or output_fields.get("container_name")
    msg = str(data.get("output", data.get("rule", "Falco event")))
    with conn() as c:
        c.execute("INSERT INTO security_events(ts,source,severity,container_name,message,raw_json) VALUES(?,?,?,?,?,?)",
                  (now(), "falco", severity, name, msg, json.dumps(data, default=str)[:100000]))
    return await decision_for_security("falco", severity, name, msg)


@app.post("/api/containers/{name}/isolate")
async def api_isolate(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await isolate(name)


@app.post("/api/containers/{name}/restore-networks")
async def api_restore_networks(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await restore_networks_from_snapshot(name)


@app.post("/api/containers/{name}/trivy")
async def api_trivy(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await trivy_scan(name)


@app.post("/api/containers/{name}/check-update")
async def check_update(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    obj = await inspect_container(name)
    image = obj.get("Config", {}).get("Image")
    result = await pull_image(image)
    event("update_check", name, result, "info")
    return result


@app.get("/api/integrations")
async def integrations(authorization: str | None = Header(default=None)):
    require_token(authorization)
    result = {
        "clamav": {"configured": bool(CLAMAV_HOST)},
        "crowdsec": {"configured": bool(CROWDSEC_URL)},
        "falco": {"configured": True},
        "trivy": {"configured": True},
        "discord": {"configured": bool(DISCORD_WEBHOOK)},
        "n8n": {"configured": bool(N8N_WEBHOOK)},
    }
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(CLAMAV_HOST, CLAMAV_PORT), timeout=2)
        writer.write(b"PING\n"); await writer.drain()
        resp = await asyncio.wait_for(reader.read(64), timeout=2)
        writer.close(); await writer.wait_closed()
        result["clamav"]["status"] = "ok" if b"PONG" in resp else "unknown"
    except Exception as e:
        result["clamav"]["status"] = "down"; result["clamav"]["detail"] = str(e)
    if CROWDSEC_URL:
        try:
            async with httpx.AsyncClient(timeout=3, verify=False) as client:
                h = {"X-Api-Key": CROWDSEC_API_KEY} if CROWDSEC_API_KEY else {}
                r = await client.get(CROWDSEC_URL.rstrip("/") + "/v1/decisions", headers=h)
                result["crowdsec"]["status"] = "ok" if r.status_code < 500 else "down"
                result["crowdsec"]["http"] = r.status_code
        except Exception as e:
            result["crowdsec"]["status"] = "down"; result["crowdsec"]["detail"] = str(e)

    with conn() as c:
        f = c.execute("SELECT ts,severity,container_name,message FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 1").fetchone()
        counts = c.execute("SELECT severity,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY severity", (now()-86400,)).fetchall()
    result["falco"]["events_24h"] = sum(r["n"] for r in counts)
    result["falco"]["counts_24h"] = {r["severity"]: r["n"] for r in counts}
    if f:
        result["falco"]["last_event_ts"] = f["ts"]
        result["falco"]["last_event_age_seconds"] = max(0, now() - int(f["ts"]))
        result["falco"]["last_container"] = f["container_name"]
        result["falco"]["last_severity"] = f["severity"]
    # Falco health is sensor liveness, not alert frequency. A quiet sensor is healthy.
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(FALCO_HOST, FALCO_HEALTH_PORT), timeout=2)
        writer.close(); await writer.wait_closed()
        result["falco"]["status"] = "ok"
        result["falco"]["detail"] = f"sensor reachable at {FALCO_HOST}:{FALCO_HEALTH_PORT}"
    except Exception as e:
        result["falco"]["status"] = "down"
        result["falco"]["detail"] = str(e)

    # Trivy is considered OK only when the runner itself responds. Scan history is reported separately.
    try:
        code, version_out = await trivy_exec(["trivy", "--version"], timeout=30)
        result["trivy"]["status"] = "ok" if code == 0 else "down"
        result["trivy"]["detail"] = version_out.strip()[-500:]
    except Exception as e:
        result["trivy"]["status"] = "down"
        result["trivy"]["detail"] = str(e)
    with conn() as c:
        t = c.execute("SELECT ts,container_name,image,status,critical,high,medium FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        tc = c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high,coalesce(sum(medium),0) medium FROM scans WHERE ts>?", (now()-86400,)).fetchone()
    result["trivy"]["scans_24h"] = tc["n"]
    result["trivy"]["critical_24h"] = tc["critical"]
    result["trivy"]["high_24h"] = tc["high"]
    if t:
        result["trivy"]["last_scan_ts"] = t["ts"]
        result["trivy"]["last_container"] = t["container_name"]
        result["trivy"]["last_scan_status"] = t["status"]
    return result


@app.get("/api/security/falco/summary")
async def falco_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cutoff = now() - 86400
    with conn() as c:
        rows = c.execute("SELECT id,ts,severity,container_name,message,raw_json FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 20").fetchall()
        counts = c.execute("SELECT severity,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY severity", (cutoff,)).fetchall()
        rule_rows = c.execute("SELECT raw_json FROM security_events WHERE source='falco' AND ts>? ORDER BY id DESC LIMIT 2000", (cutoff,)).fetchall()
        latest = c.execute("SELECT ts FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 1").fetchone()
    recent=[]
    for r in rows:
        d=dict(r); raw=d.pop("raw_json", None); rule=None
        try:
            rule=(json.loads(raw or "{}") or {}).get("rule")
        except Exception:
            pass
        d["rule"] = rule or "Falco event"
        recent.append(d)
    grouped={}
    for r in rule_rows:
        try:
            raw=json.loads(r["raw_json"] or "{}")
            rule=str(raw.get("rule") or "Falco event")
            grouped[rule]=grouped.get(rule,0)+1
        except Exception:
            grouped["Falco event"]=grouped.get("Falco event",0)+1
    top_rules=[{"rule":k,"count":v} for k,v in sorted(grouped.items(), key=lambda kv: kv[1], reverse=True)[:6]]
    return {"events_24h": sum(r["n"] for r in counts), "counts_24h": {r["severity"]: r["n"] for r in counts},
            "last_event_ts": latest["ts"] if latest else None, "last_event_age_seconds": max(0, now()-latest["ts"]) if latest else None,
            "top_rules_24h": top_rules, "recent": recent}


@app.get("/api/security/trivy/summary")
async def trivy_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    start = now() - 86400
    with conn() as c:
        scans = c.execute("SELECT id,ts,container_name,image,status,critical,high,medium FROM scans ORDER BY id DESC LIMIT 20").fetchall()
        counts = c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high,coalesce(sum(medium),0) medium FROM scans WHERE ts>?", (start,)).fetchone()
        findings = c.execute("""SELECT sf.scan_id,sf.container_name,sf.image,sf.vuln_id,sf.pkg_name,sf.installed_version,sf.fixed_version,sf.severity,sf.title
                              FROM scan_findings sf JOIN scans s ON s.id=sf.scan_id
                              WHERE s.ts>? AND sf.severity IN ('critical','high')
                              ORDER BY CASE sf.severity WHEN 'critical' THEN 0 ELSE 1 END, sf.id DESC LIMIT 30""", (start,)).fetchall()
    with conn() as c:
        sched_rows=c.execute("SELECT key,value FROM settings WHERE key LIKE 'trivy_scheduler_%'").fetchall()
    scheduler={r["key"].replace("trivy_scheduler_",""):r["value"] for r in sched_rows}
    return {"scans_24h": counts["n"], "critical_24h": counts["critical"], "high_24h": counts["high"],
            "medium_24h": counts["medium"], "recent_scans": rowdicts(scans), "top_findings": rowdicts(findings),
            "scheduler": scheduler, "auto_scan_enabled": TRIVY_AUTO_SCAN_ENABLED}


@app.get("/api/decision-engine/summary")
async def decision_engine_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cutoff24 = now()-86400
    cutoffwin = now()-DECISION_WINDOW_SECONDS
    with conn() as c:
        recent = c.execute("SELECT id,ts,container_name,score,risk,sources_json,action,executed,result FROM correlation_runs ORDER BY id DESC LIMIT 15").fetchall()
        counts = c.execute("SELECT risk,count(*) n FROM correlation_runs WHERE ts>? GROUP BY risk", (cutoff24,)).fetchall()
        srcrows = c.execute("SELECT source,count(*) n FROM security_events WHERE ts>? GROUP BY source", (cutoffwin,)).fetchall()
        trivy24 = c.execute("SELECT count(*) n FROM scans WHERE ts>?", (cutoff24,)).fetchone()["n"]
    items=[]
    for r in recent:
        d=dict(r)
        try: d["sources"] = json.loads(d.pop("sources_json"))
        except Exception: d["sources"] = []
        items.append(d)
    cmap={r["risk"]:r["n"] for r in counts}
    active={r["source"]:r["n"] for r in srcrows}
    escalations=sum(v for k,v in cmap.items() if k in {"medium","high","critical"})
    if not active and not trivy24:
        explanation="No recent security signals and no Trivy scans yet. The engine is idle, not broken."
    elif set(active.keys()) == {"falco"} and not trivy24:
        explanation=f"Falco is producing alerts, but it is only one independent source and Trivy has 0 scans. Repeated Falco alerts are intentionally not multiplied into compromise risk."
    elif len(active) <= 1:
        explanation="Only one active runtime source is contributing right now. Kingdom Manager records it but waits for independent corroboration before escalation."
    else:
        explanation=f"Independent evidence is active from {', '.join(sorted(active))}. Correlation decisions will escalate only when score and source thresholds are met."
    return {"window_seconds": DECISION_WINDOW_SECONDS, "counts_24h": cmap, "escalations_24h": escalations,
            "active_sources_window": active, "trivy_scans_24h": trivy24, "explanation": explanation, "recent": items}


async def core_sensor_health() -> dict[str, dict]:
    """Return liveness for the four core Kingdom security engines.

    Liveness is intentionally separate from alert frequency: a quiet Falco is
    healthy when its private health listener is reachable.
    """
    result = {
        "clamav": {"status": "down", "configured": bool(CLAMAV_HOST)},
        "crowdsec": {"status": "down", "configured": bool(CROWDSEC_URL)},
        "falco": {"status": "down", "configured": True},
        "trivy": {"status": "down", "configured": True},
    }
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(CLAMAV_HOST, CLAMAV_PORT), timeout=2)
        writer.write(b"PING\n"); await writer.drain()
        resp = await asyncio.wait_for(reader.read(64), timeout=2)
        writer.close(); await writer.wait_closed()
        result["clamav"]["status"] = "ok" if b"PONG" in resp else "unknown"
    except Exception as e:
        result["clamav"]["detail"] = str(e)
    if CROWDSEC_URL:
        try:
            async with httpx.AsyncClient(timeout=3, verify=False) as client:
                headers = {"X-Api-Key": CROWDSEC_API_KEY} if CROWDSEC_API_KEY else {}
                r = await client.get(CROWDSEC_URL.rstrip("/") + "/v1/decisions", headers=headers)
                result["crowdsec"]["status"] = "ok" if 200 <= r.status_code < 500 else "down"
                result["crowdsec"]["http"] = r.status_code
        except Exception as e:
            result["crowdsec"]["detail"] = str(e)
    else:
        result["crowdsec"]["status"] = "not configured"
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(FALCO_HOST, FALCO_HEALTH_PORT), timeout=2)
        writer.close(); await writer.wait_closed()
        result["falco"]["status"] = "ok"
    except Exception as e:
        result["falco"]["detail"] = str(e)
    try:
        code, version_out = await trivy_exec(["trivy", "--version"], timeout=30)
        result["trivy"]["status"] = "ok" if code == 0 else "down"
        result["trivy"]["detail"] = version_out.strip()[-500:]
    except Exception as e:
        result["trivy"]["detail"] = str(e)
    return result


@app.get("/api/security/score")
async def security_score(authorization: str | None = Header(default=None)):
    require_token(authorization)
    t=now(); cutoff=t-86400
    containers=await list_containers()
    with conn() as c:
        corr=c.execute("SELECT container_name,score,risk,action,ts FROM correlation_runs WHERE ts>? ORDER BY ts DESC",(cutoff,)).fetchall()
        scans=c.execute("SELECT container_name,critical,high,medium,ts FROM scans WHERE status='ok' AND ts>? ORDER BY ts DESC",(t-TRIVY_CONTEXT_SECONDS,)).fetchall()
        falco=c.execute("SELECT container_name,severity,message,ts FROM security_events WHERE source='falco' AND ts>? ORDER BY ts DESC",(cutoff,)).fetchall()
        sup=c.execute("SELECT count(*) n FROM correlation_runs WHERE ts>? AND action='suppressed'",(cutoff,)).fetchone()['n']
    latest_corr={}
    for r in corr:
        key=r['container_name'] or 'host'
        if key not in latest_corr: latest_corr[key]=dict(r)
    latest_scan={}
    for r in scans:
        if r['container_name'] and r['container_name'] not in latest_scan: latest_scan[r['container_name']]=dict(r)
    severity_counts={'critical':0,'high':0,'medium':0,'low':0}
    leaderboard=[]; immediate=[]
    for item in containers:
        name=item['name']; profile=risk_profile(name); raw=0; factors=[]
        cr=latest_corr.get(name)
        if cr:
            raw=max(raw,min(100,int(cr['score'])))
            if cr['risk'] in severity_counts: severity_counts[cr['risk']]+=1
            if cr['risk'] in ('critical','high'): factors.append('Decision Engine: '+cr['risk'])
        sc=latest_scan.get(name)
        if sc:
            vuln=min(35, int(sc['critical'])*12 + int(sc['high'])*4 + min(int(sc['medium']),10))
            raw=max(raw,vuln)
            if sc['critical']: factors.append(f"Trivy: {sc['critical']} critical CVE(s)")
            elif sc['high']: factors.append(f"Trivy: {sc['high']} high CVE(s)")
        weighted=min(100,round(raw*float(profile['weight'])))
        score=max(0,100-weighted)
        if score>=90: state='healthy'
        elif score>=75: state='watch'
        elif score>=55: state='elevated'
        elif score>=35: state='high risk'
        else: state='critical'
        row={'container':name,'score':score,'risk':weighted,'state':state,'profile':profile['profile'],'weight':profile['weight'],'factors':factors[:3] or ['No active correlated risk']}
        leaderboard.append(row)
        if score<55: immediate.append(row)
    leaderboard.sort(key=lambda x:(x['score'],x['container']))
    # Server score is driven by the worst containers plus breadth, not raw event count.
    risks=sorted((x['risk'] for x in leaderboard), reverse=True)
    penalty=(risks[0] if risks else 0)*0.55 + (risks[1] if len(risks)>1 else 0)*0.20 + min(sum(1 for r in risks if r>=25)*2,10)
    server_score=max(0,min(100,round(100-penalty)))

    # Monitoring confidence matters. A server cannot honestly be 100/100 while
    # one of its core sensors is unavailable, even if there is no active threat.
    sensor_health = await core_sensor_health()
    sensor_penalties = {"falco": 12, "clamav": 10, "crowdsec": 9, "trivy": 8}
    unavailable = [name for name, data in sensor_health.items() if data.get("status") != "ok"]
    confidence_penalty = sum(sensor_penalties.get(name, 5) for name in unavailable)
    server_score=max(0, server_score-confidence_penalty)

    if server_score>=90: mood,status,risk='excellent','EXCELLENT','LOW'
    elif server_score>=75: mood,status,risk='good','GOOD','LOW'
    elif server_score>=55: mood,status,risk='elevated','ELEVATED','MEDIUM'
    elif server_score>=35: mood,status,risk='high','HIGH RISK','HIGH'
    else: mood,status,risk='critical','CRITICAL','CRITICAL'
    if unavailable and server_score>=55:
        status='MONITORING DEGRADED'
    return {'score':server_score,'mood':mood,'status':status,'overall_risk':risk,'severity_counts':severity_counts,
            'immediate_attention':immediate[:6],'leaderboard':leaderboard[:12],'suppressed_24h':sup,'evaluated_ts':t,
            'sensor_health':sensor_health,'unavailable_sensors':unavailable,'monitoring_confidence':max(0,100-confidence_penalty)}


@app.get("/api/suppressions")
async def get_suppressions(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute('SELECT * FROM suppressions ORDER BY id DESC').fetchall())

@app.post("/api/suppressions")
async def add_suppression(request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json()
    source=str(d.get('source','falco')).lower(); name=d.get('container_name'); rule=str(d.get('rule_contains','')).strip(); reason=str(d.get('reason','known-good behavior'))
    if not rule: raise HTTPException(400,'rule_contains is required')
    with conn() as c:
        c.execute('INSERT OR REPLACE INTO suppressions(enabled,source,container_name,rule_contains,reason) VALUES(1,?,?,?,?)',(source,name,rule,reason))
    event('suppression',name or 'all',{'source':source,'rule':rule,'reason':reason})
    return {'ok':True}

@app.put("/api/risk-profiles/{name}")
async def set_risk_profile(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); profile=str(d.get('profile','user-app')); weight=float(d.get('weight',1.0))
    if not 0.2 <= weight <= 2.0: raise HTTPException(400,'weight must be between 0.2 and 2.0')
    with conn() as c: c.execute('INSERT OR REPLACE INTO risk_profiles(container_name,profile,weight) VALUES(?,?,?)',(name,profile,weight))
    event('risk_profile',name,{'profile':profile,'weight':weight})
    return {'container':name,'profile':profile,'weight':weight}


@app.get("/api/incidents")
async def incidents(status: str = "active", authorization: str | None = Header(default=None)):
    require_token(authorization)
    q="SELECT * FROM incidents"
    args=[]
    if status=="active": q+=" WHERE status NOT IN ('resolved','dismissed')"
    elif status!="all": q+=" WHERE status=?"; args.append(status)
    q+=" ORDER BY updated_ts DESC LIMIT 100"
    with conn() as c: rows=c.execute(q,args).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['sources']=json.loads(d.pop('sources_json') or '[]'); out.append(d)
    return out

@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        r=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        ev=c.execute("SELECT id,ts,evidence_type,label,payload FROM incident_evidence WHERE incident_id=? ORDER BY id",(incident_id,)).fetchall()
    if not r: raise HTTPException(404,'Incident not found')
    d=dict(r); d['sources']=json.loads(d.pop('sources_json') or '[]'); d['evidence']=rowdicts(ev); return d

@app.post("/api/incidents/{incident_id}/capture-evidence")
async def capture_incident_evidence(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: inc=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,'Incident not found')
    name=inc['container_name']; captured=[]
    if name:
        obj=await inspect_container(name); sid=await snapshot(name,f'incident-{incident_id}')
        payload={'snapshot_id':sid,'image':obj.get('Config',{}).get('Image'),'image_id':obj.get('Image'),'networks':list((obj.get('NetworkSettings',{}).get('Networks') or {}).keys()),'mounts':obj.get('Mounts',[]),'state':obj.get('State',{})}
        with conn() as c: c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(incident_id,now(),'container_snapshot','Docker inspect',json.dumps(payload,default=str)[:100000]))
        captured.append('container_snapshot')
        try:
            scan=await trivy_scan(name)
            with conn() as c: c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(incident_id,now(),'trivy','On-demand Trivy scan',json.dumps(scan,default=str)[:100000]))
            captured.append('trivy')
        except Exception as e: captured.append('trivy_error:'+str(e))
    event('evidence',name or 'host',{'incident_id':incident_id,'captured':captured})
    return {'ok':True,'incident_id':incident_id,'captured':captured}

@app.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); resolution=str(d.get('resolution','Resolved by operator'))
    with conn() as c: c.execute("UPDATE incidents SET status='resolved',updated_ts=?,resolution=? WHERE id=?",(now(),resolution,incident_id))
    event('incident','',{'id':incident_id,'action':'resolved','resolution':resolution}); return {'ok':True}

@app.get("/api/security/explain-score")
async def explain_score(authorization: str | None = Header(default=None)):
    require_token(authorization); ss=await security_score(authorization)
    items=[]
    for x in ss.get('leaderboard',[])[:8]:
        if x['risk']>0: items.append({'type':'container-risk','subject':x['container'],'points_lost':round(x['risk']),'detail':'; '.join(x['factors'])})
    for sensor in ss.get('unavailable_sensors',[]): items.append({'type':'sensor-confidence','subject':sensor,'points_lost':{'falco':12,'clamav':10,'crowdsec':9,'trivy':8}.get(sensor,5),'detail':'Core security sensor unavailable'})
    return {'score':ss['score'],'status':ss['status'],'monitoring_confidence':ss['monitoring_confidence'],'contributors':items,'note':'Server score weights the worst active risks; contributor points are explanatory and are not simply summed.'}

@app.put("/api/maintenance/{name}")
async def set_maintenance(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); enabled=bool(d.get('enabled',True)); minutes=max(1,min(int(d.get('minutes',60)),1440)); until=now()+minutes*60 if enabled else None; reason=str(d.get('reason','operator maintenance'))
    with conn() as c: c.execute("INSERT OR REPLACE INTO maintenance(container_name,enabled,until_ts,reason) VALUES(?,?,?,?)",(name,int(enabled),until,reason))
    event('maintenance',name,{'enabled':enabled,'until_ts':until,'reason':reason}); return {'ok':True,'enabled':enabled,'until_ts':until}

@app.post("/api/recovery/plan/{name}")
async def create_recovery_plan(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); policy=default_policy(name)
    hard_protected={'kingdom-manager','kingdom-manager-docker-api','kingdom-manager-recovery-docker-api','kingdom-manager-trivy-docker-api','kingdom-manager-trivy'}
    if name in hard_protected: raise HTTPException(409,'Kingdom core component cannot be rebuilt by automated recovery')
    if policy['protected']: raise HTTPException(409,'Protected container requires policy change before recovery')
    if not policy['allow_rebuild']: raise HTTPException(409,'allow_rebuild policy is disabled for this container')
    obj=await inspect_container(name); sid=await snapshot(name,'pre-recovery-plan'); incident_id=d.get('incident_id')
    plan={'steps':['capture evidence','isolate','pull known image','stop old container','recreate from captured configuration','start','Trivy scan','restore original networks','health observation'],'image':obj.get('Config',{}).get('Image'),'original_networks':list((obj.get('NetworkSettings',{}).get('Networks') or {}).keys()),'approval_required':True}
    t=now()
    with conn() as c:
        cur=c.execute("INSERT INTO recovery_plans(created_ts,expires_ts,container_name,incident_id,action,status,snapshot_id,plan_json) VALUES(?,?,?,?,?,?,?,?)",(t,t+RECOVERY_APPROVAL_TTL,name,incident_id,'rebuild','pending',sid,json.dumps(plan)))
    return {'plan_id':cur.lastrowid,'expires_ts':t+RECOVERY_APPROVAL_TTL,'plan':plan,'status':'pending-approval'}

async def recovery_docker(method: str,path: str,**kwargs):
    async with httpx.AsyncClient(timeout=120) as client: return await client.request(method,RECOVERY_DOCKER+path,**kwargs)

@app.post("/api/recovery/{plan_id}/approve-and-run")
async def approve_recovery(plan_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: p=c.execute("SELECT * FROM recovery_plans WHERE id=?",(plan_id,)).fetchone()
    if not p: raise HTTPException(404,'Recovery plan not found')
    if p['status']!='pending': raise HTTPException(409,'Recovery plan is not pending')
    if now()>int(p['expires_ts']): raise HTTPException(409,'Recovery approval window expired; create a new plan')
    name=p['container_name']; policy=default_policy(name)
    if policy['protected'] or not policy['allow_rebuild']: raise HTTPException(409,'Recovery policy no longer permits rebuild')
    with conn() as c: snap=c.execute("SELECT inspect_json FROM snapshots WHERE id=?",(p['snapshot_id'],)).fetchone()
    if not snap: raise HTTPException(409,'Recovery snapshot missing')
    obj=json.loads(snap['inspect_json']); image=obj.get('Config',{}).get('Image'); result={'steps':[]}
    try:
        await isolate(name); result['steps'].append('isolated')
        await pull_image(image); result['steps'].append('image-pulled')
        await recovery_docker('POST',f"/containers/{quote(name,safe='')}/stop?t=20")
        rr=await recovery_docker('DELETE',f"/containers/{quote(name,safe='')}?force=1")
        if rr.status_code not in (204,404): raise RuntimeError('remove failed: '+rr.text[:500])
        cfg=dict(obj.get('Config') or {}); cfg['HostConfig']=obj.get('HostConfig') or {}
        nets=obj.get('NetworkSettings',{}).get('Networks') or {}
        cfg['NetworkingConfig']={'EndpointsConfig':{k:{'Aliases':v.get('Aliases'),'IPAMConfig':v.get('IPAMConfig')} for k,v in nets.items() if k!=QUARANTINE_NETWORK}}
        cr=await recovery_docker('POST',f"/containers/create?name={quote(name,safe='')}",json=cfg)
        if cr.status_code!=201: raise RuntimeError('create failed: '+cr.text[:1000])
        sr=await recovery_docker('POST',f"/containers/{quote(name,safe='')}/start")
        if sr.status_code not in (204,304): raise RuntimeError('start failed: '+sr.text[:500])
        result['steps']+=['recreated','started']
        try: result['trivy']=await trivy_scan(name); result['steps'].append('trivy-scanned')
        except Exception as e: result['trivy_error']=str(e)
        with conn() as c: c.execute("UPDATE recovery_plans SET status='completed',approved_ts=?,executed_ts=?,result=? WHERE id=?",(now(),now(),json.dumps(result,default=str),plan_id))
        event('recovery',name,{'plan_id':plan_id,**result},'warning'); return {'ok':True,'plan_id':plan_id,**result}
    except Exception as e:
        result['error']=str(e)
        with conn() as c: c.execute("UPDATE recovery_plans SET status='failed',approved_ts=?,executed_ts=?,result=? WHERE id=?",(now(),now(),json.dumps(result,default=str),plan_id))
        event('recovery_failed',name,{'plan_id':plan_id,**result},'critical'); raise HTTPException(500,result)

@app.get("/api/recovery/plans")
async def recovery_plans(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute("SELECT * FROM recovery_plans ORDER BY id DESC LIMIT 50").fetchall())

@app.get("/api/events")
async def events(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


@app.get("/api/decisions")
async def decisions(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


@app.get("/api/security/events")
async def security_events(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT id,ts,source,severity,container_name,message FROM security_events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


@app.get("/api/reports/weekly")
async def weekly_report(authorization: str | None = Header(default=None)):
    require_token(authorization)
    start = now() - 7 * 86400
    cs = await list_containers()
    with conn() as c:
        sec = c.execute("SELECT severity,count(*) n FROM security_events WHERE ts>? GROUP BY severity", (start,)).fetchall()
        acts = c.execute("SELECT kind,count(*) n FROM events WHERE ts>? GROUP BY kind", (start,)).fetchall()
        scans = c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high FROM scans WHERE ts>?", (start,)).fetchone()
    return {"period_days": 7, "generated_at": now(), "containers": {"total": len(cs), "running": sum(x['state']=='running' for x in cs)},
            "security": {r['severity']: r['n'] for r in sec}, "activity": {r['kind']: r['n'] for r in acts}, "trivy": dict(scans)}


async def monitor_loop():
    await asyncio.sleep(20)
    while True:
        try:
            cs = await list_containers()
            for c in cs:
                if c["name"] in {"kingdom-manager", "kingdom-manager-docker-api", TRIVY_RUNNER}:
                    continue
                p = default_policy(c["name"])
                if c["state"] == "running":
                    stats = await sample_stats(c["name"])
                    idle, idle_since = update_idle(c["name"], stats, p)
                    # We record idle readiness; auto-update still requires an explicit update check/pull.
                    if idle:
                        event("idle", c["name"], {"cpu": stats["cpu"], "idle_since": idle_since})
                elif p["auto_restart"] and not p["protected"]:
                    status = (c.get("status") or "").lower()
                    # Restart only unexpected failures, not clean/manual exits.
                    if "exited (0)" not in status and "created" not in status:
                        r = await docker("POST", f"/containers/{quote(c['name'], safe='')}/start")
                        if r.status_code in (204, 304):
                            event("recovery", c["name"], "auto-started after unexpected stop", "warning")
                            await notify("Container recovered", f"{c['name']} was automatically started after an unexpected stop.", "warning")
        except Exception as e:
            event("monitor_error", "host", str(e), "warning")
        await asyncio.sleep(max(60, CHECK_SECONDS))


async def trivy_auto_loop():
    """Low-impact vulnerability coverage with visible scheduler state.

    Scans at most one running container per interval. Scheduler state/errors are
    persisted in settings so the dashboard can explain why scan count is zero.
    """
    await asyncio.sleep(max(10, TRIVY_AUTO_SCAN_START_DELAY_SECONDS))
    with conn() as db:
        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','starting') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    event("trivy_scheduler", "host", {"state":"started", "interval":TRIVY_AUTO_SCAN_EVERY_SECONDS}, "info")
    while True:
        target = None
        try:
            if not TRIVY_AUTO_SCAN_ENABLED:
                with conn() as db:
                    db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','disabled') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            else:
                cs = [c for c in await list_containers(False) if c.get("state") == "running"]
                excluded = {"kingdom-manager", "kingdom-manager-docker-api", "kingdom-manager-trivy", "kingdom-manager-trivy-docker-api"}
                candidates=[]
                with conn() as db:
                    for c in cs:
                        name=c["name"]
                        if name in excluded:
                            continue
                        last=db.execute("SELECT ts,status FROM scans WHERE container_name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
                        last_ts=int(last["ts"]) if last else 0
                        if last_ts == 0 or now()-last_ts >= TRIVY_RESCAN_SECONDS:
                            candidates.append((last_ts,name))
                if candidates:
                    candidates.sort(key=lambda x:(x[0],x[1]))
                    _, target=candidates[0]
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (f"scanning:{target}",))
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_attempt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now()),))
                    event("trivy_auto_scan", target, "scheduled low-impact vulnerability scan", "info")
                    result=await trivy_scan(target)
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','idle') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_success',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now()),))
                        db.execute("DELETE FROM settings WHERE key='trivy_scheduler_last_error'")
                    event("trivy_auto_complete", target, {"critical":result.get("critical",0),"high":result.get("high",0),"medium":result.get("medium",0)}, "info")
                else:
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','coverage-current') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        except Exception as e:
            msg=str(e)[:2000]
            with conn() as db:
                db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','error') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_error',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (msg,))
            event("trivy_auto_error", target or "host", msg, "warning")
        await asyncio.sleep(max(300, TRIVY_AUTO_SCAN_EVERY_SECONDS))


async def weekly_loop():
    await asyncio.sleep(60)
    while True:
        try:
            local = datetime.now(TZ)
            weekkey = f"{local.isocalendar().year}-{local.isocalendar().week}"
            with conn() as c:
                sent = c.execute("SELECT value FROM settings WHERE key='weekly_sent'").fetchone()
            if local.weekday() == 0 and local.hour >= 9 and (not sent or sent[0] != weekkey):
                # Build a compact report without requiring auth internally.
                start = now() - 7 * 86400
                cs = await list_containers()
                with conn() as c:
                    secn = c.execute("SELECT count(*) FROM security_events WHERE ts>?", (start,)).fetchone()[0]
                    decn = c.execute("SELECT count(*) FROM decisions WHERE ts>?", (start,)).fetchone()[0]
                await notify("Kingdom weekly report", f"Containers: {sum(x['state']=='running' for x in cs)}/{len(cs)} running\nSecurity events: {secn}\nDecisions: {decn}")
                with conn() as c:
                    c.execute("INSERT INTO settings(key,value) VALUES('weekly_sent',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (weekkey,))
        except Exception as e:
            event("weekly_error", "report", str(e), "warning")
        await asyncio.sleep(3600)


@app.on_event("startup")
async def startup():
    asyncio.create_task(monitor_loop())
    asyncio.create_task(trivy_auto_loop())
    asyncio.create_task(weekly_loop())


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASHBOARD)


DASHBOARD = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kingdom Manager</title>
<style>
:root{--bg:#050b12;--panel:#09131d;--line:#1c3040;--text:#eef5fa;--muted:#8fa3b5;--gold:#d8a844;--green:#4ee07d;--lime:#92e65c;--amber:#ffb02e;--red:#ff5f57;--blue:#32b7ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% -20%,#10283b 0,#07111b 30%,var(--bg) 68%);color:var(--text);font:14px Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}.wrap{max-width:1500px;margin:auto;padding:26px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{display:flex;align-items:center;gap:14px}.crest{width:54px;height:62px;border:2px solid var(--gold);clip-path:polygon(50% 0,96% 16%,88% 72%,50% 100%,12% 72%,4% 16%);display:grid;place-items:center;color:var(--gold);font-size:28px;background:#0b1620}.brand h1{font-size:25px;letter-spacing:.04em;margin:0}.muted,.tiny{color:var(--muted)}.tiny{font-size:12px}.system{display:flex;align-items:center;gap:12px}.okdot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}button,input{background:#0b1722;color:var(--text);border:1px solid #294153;border-radius:9px;padding:8px 11px}button{cursor:pointer}.hero{margin-top:22px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(115deg,#08131d,#07111a 60%,#0a1721);padding:22px;display:grid;grid-template-columns:1.2fr .75fr .72fr;gap:24px;box-shadow:0 22px 70px #0007}.scorebox{display:flex;align-items:center;gap:28px}.ring{--score:82;--mood:#4ee07d;width:180px;height:180px;border-radius:50%;background:conic-gradient(var(--mood) calc(var(--score)*1%),#18303a 0);padding:10px;filter:drop-shadow(0 0 18px #4ee07d44)}.ringin{width:100%;height:100%;border-radius:50%;background:#07111a;display:grid;place-items:center;text-align:center;border:1px solid #213745}.score{font-size:58px;font-weight:800;line-height:.9}.status{font-size:34px;font-weight:800;letter-spacing:.03em}.facewrap{display:grid;place-items:center}.facehalo{width:205px;height:205px;border-radius:50%;border:2px solid var(--gold);display:grid;place-items:center;box-shadow:0 0 0 9px #d8a8440b,0 0 38px #d8a84420}.face{width:154px;height:154px;border-radius:50%;background:radial-gradient(circle at 36% 28%,#a8ffc1 0,#5edb7a 36%,#2a9449 75%,#12612d 100%);box-shadow:inset -14px -18px 30px #002b1880,inset 10px 10px 25px #ffffff22,0 0 35px #48db7040;position:relative;transition:.4s}.eye{position:absolute;top:52px;width:17px;height:24px;border-radius:50%;background:#06120d}.eye.l{left:42px}.eye.r{right:42px}.mouth{position:absolute;left:50%;top:92px;width:62px;height:30px;transform:translateX(-50%);border-bottom:6px solid #06120d;border-radius:0 0 60px 60px;transition:.4s}.face.excellent{background:radial-gradient(circle at 36% 28%,#a8ffc1 0,#5ee58a 36%,#289c50 75%,#12612d 100%)}.face.good{background:radial-gradient(circle at 36% 28%,#d5ff9d 0,#92e65c 38%,#559d34 76%,#275d20 100%)}.face.elevated{background:radial-gradient(circle at 36% 28%,#fff1a8 0,#ffd24d 40%,#b4771d 76%,#6d4213 100%)}.face.elevated .mouth{height:5px;border-radius:0;top:105px}.face.high .mouth,.face.critical .mouth{border-bottom:0;border-top:6px solid #06120d;border-radius:60px 60px 0 0;top:106px}.face.high{background:radial-gradient(circle at 36% 28%,#ffe09b,#ffad3f 45%,#a84420 100%)}.face.critical{background:radial-gradient(circle at 36% 28%,#ffb3a9,#ff6158 45%,#8b1f27 100%)}.severity{border-left:1px solid var(--line);padding-left:22px}.sevrow{display:flex;justify-content:space-between;padding:14px 4px;border-bottom:1px solid #152b39;font-weight:700}.attention{border:1px solid #274050;border-radius:12px;padding:18px;background:#08141e}.attention-ok{text-align:center;padding:18px 4px;color:var(--green)}.check{font-size:40px}.engines{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:14px}.card{background:linear-gradient(145deg,#09141e,#07111a);border:1px solid var(--line);border-radius:13px;padding:18px;box-shadow:0 12px 35px #0004}.engine-head{display:flex;justify-content:space-between;align-items:center;font-weight:800;font-size:16px}.tag{font-size:11px;border:1px solid #294153;border-radius:999px;padding:4px 8px}.good{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--amber)}.engine-kpi{font-size:28px;margin-top:18px}.spark{height:24px;margin-top:12px;border-bottom:1px solid #183042;background:linear-gradient(175deg,transparent 55%,#32b7ff 56%,transparent 59%)}.lower{display:grid;grid-template-columns:1.35fr .95fr;gap:14px;margin-top:14px}.table{width:100%;border-collapse:collapse}.table th{text-align:left;color:var(--muted);font-size:11px;padding:10px;border-bottom:1px solid var(--line)}.table td{padding:11px 10px;border-bottom:1px solid #142634}.state{font-weight:700}.activity{max-height:360px;overflow:auto}.event{padding:11px;border-bottom:1px solid #142634;display:flex;justify-content:space-between;gap:12px}.event strong{display:block}.footer{display:flex;justify-content:space-between;gap:12px;margin:18px 0;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}.containers{margin-top:14px}.container-row{display:flex;justify-content:space-between;gap:12px;padding:12px 4px;border-bottom:1px solid #142634}.toolbar{display:flex;gap:6px;flex-wrap:wrap}.policybar{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.policybtn{font-size:11px;padding:5px 8px;border-radius:999px}.policybtn.on{border-color:#3b8d59;color:var(--green);background:#0b2117}.policybtn.off{color:var(--muted)}.policybtn.protected.on{border-color:#d8a844;color:var(--gold);background:#201806}.danger{border-color:#69323a}.login{position:fixed;inset:0;background:#04090ef2;display:flex;align-items:center;justify-content:center;z-index:10}.loginbox{width:min(440px,92vw);background:#09141e;border:1px solid #294153;border-radius:16px;padding:26px}.loginbox input{width:100%;margin:12px 0}.hidden{display:none!important}.section-title{font-size:16px;letter-spacing:.03em;margin:0 0 12px}.sev-critical{color:var(--red)}.sev-high{color:var(--amber)}.sev-medium{color:#ffd95a}.sev-low{color:var(--green)}@media(max-width:1050px){.hero{grid-template-columns:1fr}.severity{border-left:0;padding-left:0}.engines{grid-template-columns:repeat(2,1fr)}.lower{grid-template-columns:1fr}}@media(max-width:650px){.wrap{padding:14px}.scorebox{flex-direction:column;align-items:flex-start}.engines{grid-template-columns:1fr}.system{display:none}}
</style></head><body>
<div id="login" class="login"><div class="loginbox"><div class="brand"><div class="crest">♛</div><div><h1>ENTER THE KINGDOM</h1><div class="muted">Kingdom Manager secure console</div></div></div><input id="token" type="password" placeholder="Kingdom Manager token"><button onclick="saveToken()">Unlock Dashboard</button><p id="loginerr" class="bad"></p></div></div>
<div class="wrap"><div class="top"><div class="brand"><div class="crest">♛</div><div><h1>KINGDOM MANAGER</h1><div class="muted">Security Overview · Decision Engine · Container Life</div></div></div><div class="system"><span class="okdot"></span><div><b id="systemState" class="good">Checking systems</b><div id="lastCheck" class="tiny">—</div></div><button onclick="logout()">Lock</button></div></div>
<section class="hero"><div><h2 class="section-title">KINGDOM SECURITY SCORE</h2><div class="scorebox"><div id="scoreRing" class="ring"><div class="ringin"><div><div id="score" class="score">—</div><div class="muted">/100</div></div></div></div><div><div id="scoreStatus" class="status">CHECKING</div><h3>Overall Risk: <span id="overallRisk">—</span></h3><p id="scoreText" class="muted">Evaluating independent security engines and container risk.</p><div class="tiny"><span id="suppressed">0</span> known-good signals suppressed in 24h</div></div></div></div><div class="facewrap"><div class="facehalo"><div id="moodFace" class="face"><span class="eye l"></span><span class="eye r"></span><span class="mouth"></span></div></div><div class="tiny" style="margin-top:12px">KINGDOM SENTINEL</div></div><div class="severity"><div class="sevrow sev-critical"><span>⬡ CRITICAL</span><span id="sevCritical">0</span></div><div class="sevrow sev-high"><span>⬡ HIGH</span><span id="sevHigh">0</span></div><div class="sevrow sev-medium"><span>⬡ MEDIUM</span><span id="sevMedium">0</span></div><div class="sevrow sev-low"><span>⬡ LOW</span><span id="sevLow">0</span></div><div id="attention" class="attention" style="margin-top:16px"><h3>IMMEDIATE ATTENTION</h3><div class="attention-ok"><div class="check">✓</div>No incidents require immediate attention.</div></div></div></section>
<div id="engines" class="engines"></div><div class="lower"><div class="card"><h2 class="section-title">🚨 INCIDENT CENTER</h2><div id="incidents" class="activity"></div></div><div class="card"><h2 class="section-title">🧠 EXPLAIN MY SCORE</h2><div id="scoreExplain" class="activity"></div></div></div><div class="lower"><div class="card"><h2 class="section-title">CONTAINER RISK LEADERBOARD</h2><table class="table"><thead><tr><th>CONTAINER</th><th>SCORE</th><th>STATE</th><th>PROFILE</th><th>TOP RISK FACTOR</th></tr></thead><tbody id="leaderboard"></tbody></table></div><div class="card"><h2 class="section-title">RECENT KINGDOM ACTIVITY</h2><div id="activity" class="activity"></div></div></div><div class="card containers"><h2 class="section-title">CONTAINER LIFE & CONTROLS</h2><div id="containers"></div></div><div class="footer"><span>🧠 Decision Engine <b class="good">Active</b></span><span>🛡 Independent-source correlation</span><span id="footerEval">Last evaluation —</span><span>v1.6.1 · UI Recovery Policies + Incident Response ♛</span></div></div>
<script>
let TOKEN=localStorage.getItem('km_token')||'';function hdr(){return {'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}}async function api(url,opt={}){opt.headers={...(opt.headers||{}),...hdr()};let r=await fetch(url,opt);if(r.status===401){document.getElementById('login').classList.remove('hidden');throw Error('Unauthorized')}let t=await r.text(),d=t?JSON.parse(t):{};if(!r.ok)throw Error(d.detail||t);return d}function saveToken(){TOKEN=document.getElementById('token').value.trim();localStorage.setItem('km_token',TOKEN);load().then(()=>document.getElementById('login').classList.add('hidden')).catch(e=>document.getElementById('loginerr').textContent=e.message)}function logout(){localStorage.removeItem('km_token');TOKEN='';document.getElementById('login').classList.remove('hidden')}function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}function age(sec){if(sec==null)return'never';if(sec<60)return sec+'s ago';if(sec<3600)return Math.floor(sec/60)+'m ago';return Math.floor(sec/3600)+'h ago'}async function act(n,a){if((a==='stop'||a==='isolate')&&!confirm(`${a.toUpperCase()} ${n}?`))return;try{await api(`/api/containers/${encodeURIComponent(n)}/${a}`,{method:'POST'});load()}catch(e){alert(e.message)}}async function scan(n){try{let d=await api(`/api/containers/${encodeURIComponent(n)}/trivy`,{method:'POST'});alert(`Trivy ${n}: Critical ${d.critical}, High ${d.high}, Medium ${d.medium}`);load()}catch(e){alert(e.message)}}async function upd(n){try{let d=await api(`/api/containers/${encodeURIComponent(n)}/check-update`,{method:'POST'});alert(d.update_available?'New image pulled; container was not recreated automatically.':'No image ID change detected.');load()}catch(e){alert(e.message)}}async function policy(n,key,value){try{await api(`/api/policies/${encodeURIComponent(n)}`,{method:'PUT',body:JSON.stringify({[key]:value})});load()}catch(e){alert(e.message)}}function policyButton(n,label,key,on,extra=''){return `<button class="policybtn ${on?'on':'off'} ${extra}" onclick="policy('${esc(n)}','${key}',${on?'false':'true'})">${on?'✓':'○'} ${label}</button>`}function engineCard(name,icon,status,body){return `<div class="card"><div class="engine-head"><span>${icon} ${name.toUpperCase()}</span><span class="tag ${status==='ok'?'good':status==='down'?'bad':'warn'}">${esc(status||'ready').toUpperCase()}</span></div>${body}<div class="spark"></div></div>`}
async function load(){let [ins,fs,ts,ss,ev,cs,incs,explain]=await Promise.all([api('/api/integrations'),api('/api/security/falco/summary'),api('/api/security/trivy/summary'),api('/api/security/score'),api('/api/events?limit=35'),api('/api/containers'),api('/api/incidents'),api('/api/security/explain-score')]);document.getElementById('incidents').innerHTML=incs.length?incs.slice(0,8).map(i=>`<div class="event"><div><strong class="${i.severity==='critical'?'bad':i.severity==='high'?'warn':''}">#${i.id} ${esc(i.container_name||'host')} · ${esc(i.severity).toUpperCase()}</strong><span class="tiny">${esc(i.title)} · ${esc((i.sources||[]).join(', '))}</span></div><span class="tag warn">${esc(i.status)}</span></div>`).join(''):'<div class="attention-ok">✓ No active incidents.</div>';document.getElementById('scoreExplain').innerHTML=(explain.contributors||[]).length?(explain.contributors||[]).slice(0,8).map(x=>`<div class="event"><div><strong>${esc(x.subject)}</strong><span class="tiny">${esc(x.detail)}</span></div><b>−${x.points_lost}</b></div>`).join(''):'<div class="attention-ok">✓ No active deductions.</div>';let healthy=Object.values(ins).filter(x=>x.configured).every(x=>x.status==='ok');document.getElementById('systemState').textContent=healthy?'All Systems Operational':'Review Security Engines';document.getElementById('systemState').className=healthy?'good':'warn';document.getElementById('lastCheck').textContent='Last check: just now';let ring=document.getElementById('scoreRing'),color=ss.score>=90?'#4ee07d':ss.score>=75?'#92e65c':ss.score>=55?'#ffd24d':ss.score>=35?'#ff9f35':'#ff5f57';ring.style.setProperty('--score',ss.score);ring.style.setProperty('--mood',color);document.getElementById('score').textContent=ss.score;let st=document.getElementById('scoreStatus');st.textContent=ss.status;st.style.color=color;document.getElementById('overallRisk').textContent=ss.overall_risk;document.getElementById('scoreText').textContent=(ss.unavailable_sensors||[]).length?`Monitoring degraded: ${(ss.unavailable_sensors||[]).join(', ')} unavailable. Risk score includes a sensor-confidence penalty.`:ss.score>=90?'Your Kingdom is secure. No significant correlated threats are active.':ss.score>=75?'Your Kingdom is stable. A few signals deserve observation.':ss.score>=55?'Elevated activity detected. Review the risk leaderboard.':ss.score>=35?'High-risk evidence needs investigation.':'Critical correlated risk requires immediate attention.';document.getElementById('suppressed').textContent=ss.suppressed_24h||0;document.getElementById('moodFace').className='face '+ss.mood;let halo=document.querySelector('.facehalo');halo.style.borderColor=color;halo.style.boxShadow=`0 0 0 9px ${color}12,0 0 42px ${color}35`;let sc=ss.severity_counts||{};['Critical','High','Medium','Low'].forEach(k=>document.getElementById('sev'+k).textContent=sc[k.toLowerCase()]||0);let att=ss.immediate_attention||[];document.getElementById('attention').innerHTML='<h3>IMMEDIATE ATTENTION</h3>'+(att.length?att.map(x=>`<div class="event"><div><strong class="${x.score<35?'sev-critical':'sev-high'}">${esc(x.container)} · ${esc(x.state)}</strong><span class="tiny">${esc(x.factors[0])}</span></div><b>${x.score}</b></div>`).join(''):'<div class="attention-ok"><div class="check">✓</div>No incidents require immediate attention.</div>');let fc=fs.counts_24h||{};document.getElementById('engines').innerHTML=engineCard('Falco','🦅',ins.falco.status,`<div class="engine-kpi">${fs.events_24h||0}</div><div class="tiny">Events (24h) · <span class="sev-critical">${fc.critical||0} critical</span> · <span class="sev-high">${fc.high||0} high</span><br>Last event ${age(fs.last_event_age_seconds)}</div>`)+engineCard('Trivy','◇',ins.trivy.status,`<div class="engine-kpi">${ts.scans_24h||0}</div><div class="tiny">Scans (24h) · <span class="sev-critical">${ts.critical_24h||0} critical</span> · <span class="sev-high">${ts.high_24h||0} high</span><br>Scheduler: ${esc((ts.scheduler||{}).state|| (ts.auto_scan_enabled?'starting':'disabled'))}${(ts.scheduler||{}).last_error?'<br><span class="bad">'+esc((ts.scheduler||{}).last_error).slice(0,110)+'</span>':''}</div>`)+engineCard('ClamAV','⬡',ins.clamav.status,`<div class="engine-kpi">${ins.clamav.status==='ok'?'Clean':'Review'}</div><div class="tiny">Malware scanning sensor</div>`)+engineCard('CrowdSec','♜',ins.crowdsec.status,`<div class="engine-kpi">${ins.crowdsec.status==='ok'?'Active':'Review'}</div><div class="tiny">Host intrusion decisions & firewall context</div>`);document.getElementById('leaderboard').innerHTML=(ss.leaderboard||[]).map(x=>`<tr><td><b>${esc(x.container)}</b></td><td><b>${x.score}</b></td><td class="state ${x.score>=75?'good':x.score>=55?'warn':'bad'}">${esc(x.state).toUpperCase()}</td><td>${esc(x.profile)}</td><td class="tiny">${esc(x.factors[0])}</td></tr>`).join('');document.getElementById('activity').innerHTML=ev.map(e=>`<div class="event"><div><strong>${esc(e.subject||e.kind)}</strong><span class="tiny">${esc(e.detail).slice(0,150)}</span></div><span class="tiny">${new Date(e.ts*1000).toLocaleTimeString()}</span></div>`).join('');document.getElementById('containers').innerHTML=cs.map(c=>{let p=c.policy||{};return `<div class="container-row"><div style="min-width:0"><b>${esc(c.name)}</b> <span class="tag ${c.state==='running'?'good':'bad'}">${esc(c.state)}</span><div class="tiny">${esc(c.image)} · ${esc(c.status)}</div><div class="policybar">${policyButton(c.name,'Approved Rebuild','allow_rebuild',!!p.allow_rebuild)}${policyButton(c.name,'Auto-Isolate','auto_isolate',!!p.auto_isolate)}${policyButton(c.name,'Auto-Restart','auto_restart',!!p.auto_restart)}${policyButton(c.name,'Protected','protected',!!p.protected,'protected')}</div></div><div class="toolbar"><button onclick="act('${esc(c.name)}','start')">Start</button><button onclick="act('${esc(c.name)}','restart')">Restart</button><button class="danger" onclick="act('${esc(c.name)}','stop')">Stop</button><button onclick="scan('${esc(c.name)}')">Trivy</button><button onclick="upd('${esc(c.name)}')">Update</button><button class="danger" onclick="act('${esc(c.name)}','isolate')">Isolate</button></div></div>`}).join('');document.getElementById('footerEval').textContent='Last full evaluation '+new Date(ss.evaluated_ts*1000).toLocaleTimeString()}
if(TOKEN){load().then(()=>document.getElementById('login').classList.add('hidden')).catch(()=>{})}setInterval(()=>{if(TOKEN)load().catch(()=>{})},30000)
</script></body></html>
'''
