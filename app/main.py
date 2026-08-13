from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app.core.config import settings
from app.core.db import init_db
from app.services.docker_service import DockerService
from app.services.activity_service import ActivityService
from app.services.policy_service import PolicyService
from app.security.adapters import SecurityAdapterRegistry
from app.workflows.engine import WorkflowEngine


docker_service = DockerService()
activity_service = ActivityService()
policy_service = PolicyService()
security_registry = SecurityAdapterRegistry()
workflow_engine = WorkflowEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, version='0.1.0', lifespan=lifespan)


@app.get('/health')
def health():
    docker_ok = docker_service.ping()
    return {
        'status': 'healthy' if docker_ok else 'degraded',
        'docker': docker_ok,
        'mutations_enabled': settings.enable_mutations,
        'version': '0.1.0',
    }


@app.get('/api/containers')
def containers():
    try:
        result = docker_service.containers()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f'Docker unavailable: {exc}') from exc
    for item in result:
        item['activity'] = activity_service.classify(item)
    return result


@app.get('/api/containers/{name}')
def container_detail(name: str):
    try:
        return docker_service.inspect(name)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get('/api/security')
def security_status():
    return {'integrations': security_registry.status()}


@app.get('/api/workflows')
def workflow_status():
    return {'workflows': workflow_engine.list_workflows()}


@app.get('/', response_class=HTMLResponse)
def dashboard():
    try:
        items = docker_service.containers()
    except Exception as exc:
        return HTMLResponse(f'<h1>Kingdom Manager</h1><p>Docker unavailable: {exc}</p>', status_code=503)

    rows = []
    for item in items:
        activity = activity_service.classify(item)
        rows.append(
            f"<tr><td>{item['name']}</td><td>{item['status']}</td><td>{item['health']}</td>"
            f"<td>{item['image']}</td><td>{activity['state']}</td><td>{activity['reason']}</td></tr>"
        )

    html = '''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kingdom Manager</title>
<style>
body{font-family:system-ui;background:#11131a;color:#eee;margin:2rem}h1{margin-bottom:.25rem}.sub{color:#aaa;margin-top:0}
table{border-collapse:collapse;width:100%;background:#191c25}th,td{padding:.7rem;border-bottom:1px solid #2b3040;text-align:left;font-size:.9rem}th{color:#c6b7ff}.badge{padding:.2rem .45rem;border-radius:.35rem;background:#2b3040}
</style></head><body>
<h1>👑 Kingdom Manager</h1><p class="sub">v0.1 · read-only observation mode</p>
<table><thead><tr><th>Container</th><th>Status</th><th>Health</th><th>Image</th><th>Activity</th><th>Reason</th></tr></thead><tbody>'''
    html += ''.join(rows)
    html += '</tbody></table></body></html>'
    return HTMLResponse(html)
