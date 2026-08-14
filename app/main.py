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

VERSION = "1.2.0"
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
        # A vulnerable image is not the same thing as an active compromise. Do not isolate it.
        # Feed a recommendation into the Decision Engine instead.
        decision_name = "recommend_update" if counts["critical"] else "investigate_update"
        reason = f"trivy: {counts['critical']} critical and {counts['high']} high vulnerabilities in {image}"
        with conn() as c:
            cur = c.execute("INSERT INTO decisions(ts,container_name,decision,reason,executed) VALUES(?,?,?,?,0)",
                            (now(), name, decision_name, reason))
            decision = {"id": cur.lastrowid, "decision": decision_name, "executed": False}
        if counts["critical"]:
            await notify("Critical image vulnerabilities", f"{name} ({image}) has {counts['critical']} critical and {counts['high']} high findings. No automatic isolation was performed.", "critical")

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


async def decision_for_security(source: str, severity: str, name: str | None, message: str) -> dict:
    sev = severity.lower()
    decision = "record"
    execute = False
    reason = f"{source}: {message}"
    if name:
        p = default_policy(name)
        if sev == "critical":
            decision = "isolate" if p["auto_isolate"] and not p["protected"] else "recommend_isolation"
            execute = decision == "isolate"
        elif sev == "high":
            decision = "investigate"
        elif source.lower() == "clamav" and "infect" in message.lower():
            decision = "isolate" if p["auto_isolate"] and not p["protected"] else "recommend_isolation"
            execute = decision == "isolate"
    with conn() as c:
        cur = c.execute("INSERT INTO decisions(ts,container_name,decision,reason,executed) VALUES(?,?,?,?,?)",
                        (now(), name, decision, reason, int(execute)))
        did = cur.lastrowid
    result = None
    if execute and name:
        try:
            result = await isolate(name)
        except Exception as e:
            result = {"error": str(e)}
    if sev in {"high", "critical"}:
        await notify(f"Security {severity.upper()}: {source}", f"{name or 'host'} — {message}\nDecision: {decision}", sev)
    return {"id": did, "decision": decision, "executed": execute, "result": result}


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
        age = now() - int(f["ts"])
        result["falco"]["last_event_ts"] = f["ts"]
        result["falco"]["last_container"] = f["container_name"]
        result["falco"]["last_severity"] = f["severity"]
        result["falco"]["status"] = "ok" if age <= 300 else "stale"
    else:
        result["falco"]["status"] = "waiting"

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
    with conn() as c:
        rows = c.execute("SELECT id,ts,severity,container_name,message FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 20").fetchall()
        counts = c.execute("SELECT severity,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY severity", (now()-86400,)).fetchall()
    return {"events_24h": sum(r["n"] for r in counts), "counts_24h": {r["severity"]: r["n"] for r in counts}, "recent": rowdicts(rows)}


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
    return {"scans_24h": counts["n"], "critical_24h": counts["critical"], "high_24h": counts["high"],
            "medium_24h": counts["medium"], "recent_scans": rowdicts(scans), "top_findings": rowdicts(findings)}


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
    asyncio.create_task(weekly_loop())


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASHBOARD)


DASHBOARD = r'''<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kingdom Manager</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui;color:#f4f0ff;background:#09070d}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#211431 0,#0d0a12 42%,#09070d 100%);min-height:100vh}.wrap{max-width:1450px;margin:auto;padding:24px}.top{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}.brand h1{margin:0;font-size:32px}.muted{color:#a79eb5}.pill{padding:7px 11px;border:1px solid #3f3154;border-radius:999px;background:#17111f}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:16px}.card{grid-column:span 3;background:rgba(24,18,32,.88);border:1px solid #342741;border-radius:16px;padding:16px;box-shadow:0 12px 40px #0005}.wide{grid-column:span 8}.side{grid-column:span 4}.full{grid-column:1/-1}.kpi{font-size:28px;font-weight:800}.good{color:#89e6ac}.bad{color:#ff8d9a}.warn{color:#f2c864}.row{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #2d2338}.row:last-child{border:0}.name{font-weight:700}.tiny{font-size:12px;color:#a79eb5}button,input,select{border:1px solid #49375d;border-radius:9px;background:#1a1322;color:#fff;padding:8px 10px}button{cursor:pointer}button:hover{background:#2c1e3a}.danger{border-color:#7f3340}.gold{color:#e8c260}.toolbar{display:flex;gap:6px;flex-wrap:wrap}.tag{font-size:11px;border:1px solid #41314e;border-radius:999px;padding:3px 7px}.scroll{max-height:560px;overflow:auto}.login{position:fixed;inset:0;background:#09070df2;display:flex;align-items:center;justify-content:center;z-index:5}.loginbox{width:min(420px,92vw);background:#17111f;border:1px solid #443255;border-radius:18px;padding:24px}.loginbox input{width:100%;margin:12px 0}.hidden{display:none!important}pre{white-space:pre-wrap;word-break:break-word;font-size:12px}.sev-critical{color:#ff6f7f}.sev-high{color:#ffc067}@media(max-width:1000px){.card,.wide,.side{grid-column:1/-1}}
</style></head><body>
<div id="login" class="login"><div class="loginbox"><h2>👑 Enter the Kingdom</h2><p class="muted">Paste your <code>KM_API_TOKEN</code>. It stays only in this browser.</p><input id="token" type="password" placeholder="Kingdom Manager token"><button onclick="saveToken()">Unlock Dashboard</button><p id="loginerr" class="bad"></p></div></div>
<div class="wrap"><div class="top"><div class="brand"><h1>👑 Kingdom Manager</h1><div class="muted">Container Life · Security Engine · Decision Engine · Recovery · Reports</div></div><div class="toolbar"><span id="health" class="pill">Checking…</span><button onclick="logout()">Lock</button></div></div>
<div class="grid">
<div class="card"><div class="muted">Containers</div><div id="kTotal" class="kpi">—</div></div><div class="card"><div class="muted">Running</div><div id="kRunning" class="kpi good">—</div></div><div class="card"><div class="muted">Security / 24h</div><div id="kSecurity" class="kpi warn">—</div></div><div class="card"><div class="muted">Decisions / 24h</div><div id="kDecisions" class="kpi gold">—</div></div>
<div class="card wide"><h2>🐳 Container Life</h2><div id="containers" class="scroll">Loading…</div></div>
<div class="card side"><h2>🛡️ Security Engines</h2><div id="integrations">Loading…</div><div id="falcoSummary"></div><div id="trivySummary"></div><h3>🧠 Decision Engine</h3><div class="muted">Critical events can isolate containers only when that container's policy explicitly enables Auto-Isolate.</div></div>
<div class="card full"><h2>📜 Recent Kingdom Activity</h2><div id="events" class="scroll"></div></div>
</div></div>
<script>
let TOKEN=localStorage.getItem('km_token')||'';
function hdr(){return {'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}}
async function api(url,opt={}){opt.headers={...(opt.headers||{}),...hdr()};let r=await fetch(url,opt);if(r.status===401){document.getElementById('login').classList.remove('hidden');throw Error('Unauthorized')}let t=await r.text();let d=t?JSON.parse(t):{};if(!r.ok)throw Error(d.detail||t);return d}
function saveToken(){TOKEN=document.getElementById('token').value.trim();localStorage.setItem('km_token',TOKEN);load().then(()=>document.getElementById('login').classList.add('hidden')).catch(e=>document.getElementById('loginerr').textContent=e.message)}
function logout(){localStorage.removeItem('km_token');TOKEN='';document.getElementById('login').classList.remove('hidden')}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function act(n,a){if((a==='stop'||a==='isolate')&&!confirm(`${a.toUpperCase()} ${n}?`))return;try{await api(`/api/containers/${encodeURIComponent(n)}/${a}`,{method:'POST'});await load()}catch(e){alert(e.message)}}
async function scan(n){try{let d=await api(`/api/containers/${encodeURIComponent(n)}/trivy`,{method:'POST'});alert(`Trivy ${n}: Critical ${d.critical}, High ${d.high}, Medium ${d.medium}, Total ${d.total}`);load()}catch(e){alert(e.message)}}
async function upd(n){try{let d=await api(`/api/containers/${encodeURIComponent(n)}/check-update`,{method:'POST'});alert(d.update_available?'New image pulled; container has NOT been recreated automatically.':'No image ID change detected.');load()}catch(e){alert(e.message)}}
async function setFlag(n,k,v){try{await api(`/api/policies/${encodeURIComponent(n)}`,{method:'PUT',body:JSON.stringify({[k]:v})});load()}catch(e){alert(e.message)}}
function policy(n,p){return `<div class="tiny">Policy: <label><input type="checkbox" ${p.auto_restart?'checked':''} onchange="setFlag('${esc(n)}','auto_restart',this.checked)"> recovery</label> · <label><input type="checkbox" ${p.auto_isolate?'checked':''} onchange="setFlag('${esc(n)}','auto_isolate',this.checked)"> auto-isolate</label> · <label><input type="checkbox" ${p.protected?'checked':''} onchange="setFlag('${esc(n)}','protected',this.checked)"> protected</label></div>`}
async function load(){
 let o=await api('/api/overview');document.getElementById('kTotal').textContent=o.containers;document.getElementById('kRunning').textContent=o.running;document.getElementById('kSecurity').textContent=o.security_24h;document.getElementById('kDecisions').textContent=o.decisions_24h;document.getElementById('health').textContent='Kingdom Manager v'+o.version;
 let cs=await api('/api/containers');document.getElementById('containers').innerHTML=cs.map(c=>`<div class="row"><div><div class="name">${esc(c.name)} <span class="tag ${c.state==='running'?'good':'bad'}">${esc(c.state)}</span></div><div class="tiny">${esc(c.image)} · ${esc(c.status)}</div>${policy(c.name,c.policy)}</div><div class="toolbar"><button onclick="act('${esc(c.name)}','start')">Start</button><button onclick="act('${esc(c.name)}','restart')">Restart</button><button class="danger" onclick="act('${esc(c.name)}','stop')">Stop</button><button onclick="scan('${esc(c.name)}')">Trivy</button><button onclick="upd('${esc(c.name)}')">Update Check</button><button class="danger" onclick="act('${esc(c.name)}','isolate')">Isolate</button></div></div>`).join('');
 let ins=await api('/api/integrations');document.getElementById('integrations').innerHTML=Object.entries(ins).map(([k,v])=>`<div class="row"><span>${esc(k)}</span><span class="tag ${v.status==='ok'?'good':v.status==='down'?'bad':v.status==='stale'?'warn':''}">${esc(v.status|| (v.configured?'ready':'not configured'))}</span></div>`).join('');
 let fs=await api('/api/security/falco/summary');let fc=fs.counts_24h||{};document.getElementById('falcoSummary').innerHTML=`<h3>🦅 Falco / 24h</h3><div class="tiny">Events: <b>${fs.events_24h||0}</b> · Critical: <b class="sev-critical">${fc.critical||0}</b> · High: <b class="sev-high">${fc.high||0}</b></div>`+(fs.recent||[]).slice(0,5).map(e=>`<div class="row"><div><b class="sev-${esc(e.severity)}">${esc(e.severity)}</b> · ${esc(e.container_name||'host')}<div class="tiny">${esc(e.message).slice(0,180)}</div></div></div>`).join('');
 let ts=await api('/api/security/trivy/summary');document.getElementById('trivySummary').innerHTML=`<h3>🔎 Trivy / 24h</h3><div class="tiny">Scans: <b>${ts.scans_24h||0}</b> · Critical: <b class="sev-critical">${ts.critical_24h||0}</b> · High: <b class="sev-high">${ts.high_24h||0}</b> · Medium: <b>${ts.medium_24h||0}</b></div>`+(ts.top_findings||[]).slice(0,5).map(v=>`<div class="row"><div><b class="sev-${esc(v.severity)}">${esc(v.severity)}</b> · ${esc(v.container_name||'image')}<div class="tiny">${esc(v.vuln_id)} · ${esc(v.pkg_name)} ${esc(v.installed_version)}${v.fixed_version?' → '+esc(v.fixed_version):''}</div></div></div>`).join('');
 let ev=await api('/api/events?limit=80');document.getElementById('events').innerHTML=ev.map(e=>`<div class="row"><div><b class="sev-${esc(e.severity)}">${esc(e.kind)}</b> · ${esc(e.subject)}<div class="tiny">${new Date(e.ts*1000).toLocaleString()} · ${esc(e.detail)}</div></div></div>`).join('');
}
if(TOKEN){load().then(()=>document.getElementById('login').classList.add('hidden')).catch(()=>{})}
setInterval(()=>{if(TOKEN)load().catch(()=>{})},30000)
</script></body></html>'''
