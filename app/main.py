from contextlib import asynccontextmanager
from html import escape

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.config import settings
from app.core.db import init_db
from app.integrations.registry import list_integrations as integration_catalog
from app.integrations.service import IntegrationService
from app.security.adapters import SecurityAdapterRegistry
from app.services.activity_service import ActivityService
from app.services.classification_service import ClassificationService
from app.services.docker_service import DockerService
from app.services.policy_service import PolicyService
from app.workflows.engine import WorkflowEngine


docker_service = DockerService()
integration_service = IntegrationService()
activity_service = ActivityService()
classification_service = ClassificationService()
policy_service = PolicyService()
security_registry = SecurityAdapterRegistry()
workflow_engine = WorkflowEngine()
VERSION = '0.3.0'


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, version=VERSION, lifespan=lifespan)


@app.get('/health')
def health():
    docker_ok = docker_service.ping()
    return {
        'status': 'healthy' if docker_ok else 'degraded',
        'docker': docker_ok,
        'mutations_enabled': settings.enable_mutations,
        'version': VERSION,
    }


def enrich(item: dict) -> dict:
    classification = classification_service.classify(item)
    activity = activity_service.classify(item, classification)
    interruption = policy_service.interruption_decision(activity=activity, classification=classification)
    return {**item, 'classification': classification, 'activity': activity, 'interruption': interruption}


@app.get('/api/containers')
def containers():
    try:
        result = docker_service.containers()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f'Docker unavailable: {exc}') from exc
    return [enrich(item) for item in result]


@app.get('/api/stacks')
def stacks():
    try:
        items = [enrich(item) for item in docker_service.containers()]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f'Docker unavailable: {exc}') from exc
    grouped = {}
    for item in items:
        stack = item['classification'].get('stack') or 'standalone'
        grouped.setdefault(stack, []).append(item)
    return {'stacks': grouped}


@app.get('/api/containers/{name}')
def container_detail(name: str):
    try:
        base = next(item for item in docker_service.containers() if item['name'] == name)
        return {**docker_service.inspect(name), **enrich(base)}
    except StopIteration as exc:
        raise HTTPException(status_code=404, detail='container not found') from exc
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get('/api/integrations')
def integrations_api():
    return {
        'catalog': integration_catalog(),
        'configured': integration_service.list(),
    }


@app.post('/api/integrations/{integration_id}/test')
def test_integration_api(integration_id: int):
    return integration_service.test(integration_id)


@app.get('/api/security')
def security_status():
    return {'integrations': security_registry.status()}


@app.get('/api/workflows')
def workflow_status():
    return {'workflows': workflow_engine.list_workflows()}


@app.get('/integrations', response_class=HTMLResponse)
def integrations_page(message: str = ''):
    configured = integration_service.list()
    catalog = integration_catalog()
    try:
        container_names = [c['name'] for c in docker_service.containers()]
    except Exception:
        container_names = []

    cards = []
    for item in configured:
        cards.append(
            "<div class='card'>"
            f"<h3>{escape(item['name'])}</h3>"
            f"<p><b>Type:</b> {escape(item['kind'])}<br>"
            f"<b>Container:</b> {escape(item.get('container_name') or 'not linked')}<br>"
            f"<b>Mode:</b> {escape(item['permission_mode'])}<br>"
            f"<b>URL:</b> {escape(item['base_url'])}<br>"
            f"<b>Credential:</b> {escape(item['credential_masked'])}</p>"
            f"<form method='post' action='/integrations/{item['id']}/test' class='inline'><button>Test</button></form> "
            f"<form method='post' action='/integrations/{item['id']}/delete' class='inline' onsubmit=\"return confirm('Delete this integration?')\"><button class='danger'>Delete</button></form>"
            "</div>"
        )

    type_options = ''.join(
        f"<option value='{escape(x['type'])}'>{escape(x['name'])}</option>" for x in catalog
    )
    container_options = "<option value=''>-- choose container --</option>" + ''.join(
        f"<option value='{escape(name)}'>{escape(name)}</option>" for name in container_names
    )
    notice = f"<div class='notice'>{escape(message)}</div>" if message else ''

    html = f'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kingdom Manager Integrations</title>
<style>
body{{font-family:system-ui;background:#11131a;color:#eee;margin:2rem;max-width:1100px}}a{{color:#bba7ff}}.sub{{color:#aaa}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}}.card{{background:#191c25;border:1px solid #2b3040;border-radius:.8rem;padding:1rem}}
form.panel{{background:#191c25;border:1px solid #2b3040;border-radius:.8rem;padding:1rem;margin-top:1rem}}label{{display:block;margin:.7rem 0 .25rem;color:#c6b7ff}}input,select{{width:100%;box-sizing:border-box;padding:.65rem;background:#101219;color:#eee;border:1px solid #394052;border-radius:.45rem}}
button{{padding:.55rem .8rem;background:#3f326d;color:white;border:0;border-radius:.45rem;cursor:pointer}}.danger{{background:#6c2424}}.inline{{display:inline}}.notice{{background:#183c2b;border:1px solid #2c6b4b;padding:.8rem;border-radius:.6rem;margin:1rem 0}}
.warn{{background:#402f13;border:1px solid #72541c;padding:1rem;border-radius:.6rem}}code{{color:#d5c8ff}}
</style></head><body>
<p><a href='/'>← Dashboard</a></p>
<h1>🔌 Integrations</h1><p class='sub'>v0.3 · least-privilege service awareness</p>
<div class='warn'><b>Local-server security:</b> Kingdom Manager can store service API credentials. Keep it on a trusted LAN/VPN, never expose it directly to the public Internet, and grant only the minimum read permissions needed for activity detection. Credentials are encrypted at rest and masked in the UI.</div>
{notice}
<h2>Configured</h2><div class='grid'>{''.join(cards) if cards else "<div class='card'>No integrations configured yet.</div>"}</div>
<h2>Add integration</h2>
<form class='panel' method='post' action='/integrations'>
<label>Integration type</label><select name='kind' id='kind'>{type_options}</select>
<label>Display name</label><input name='name' placeholder='Jellyfin'>
<label>Container</label><select name='container_name'>{container_options}</select>
<label>Internal service URL</label><input name='base_url' placeholder='http://jellyfin:8096' required>
<label>Permission mode</label><select name='permission_mode'><option>MONITOR</option><option>OBSERVE</option><option>MANAGE</option><option>PROTECTED</option></select>
<label>API key / bearer token</label><input type='password' name='credential' autocomplete='new-password' placeholder='Stored encrypted; leave blank only if endpoint needs no auth'>
<h3>Generic HTTP options</h3><p class='sub'>Only used when Integration type is Generic HTTP.</p>
<label>Status path</label><input name='generic_path' placeholder='/api/status'>
<label>JSON field</label><input name='generic_field' placeholder='jobs.running'>
<label>Busy comparison</label><select name='generic_operator'><option value='gt'>&gt;</option><option value='gte'>&gt;=</option><option value='eq'>=</option><option value='ne'>!=</option><option value='lt'>&lt;</option><option value='lte'>&lt;=</option></select>
<label>Comparison value</label><input name='generic_value' value='0'>
<p><button type='submit'>Save integration</button></p>
</form>
</body></html>'''
    return HTMLResponse(html)


@app.post('/integrations')
def create_integration(
    kind: str = Form(...),
    name: str = Form(''),
    container_name: str = Form(''),
    base_url: str = Form(...),
    permission_mode: str = Form('MONITOR'),
    credential: str = Form(''),
    generic_path: str = Form(''),
    generic_field: str = Form(''),
    generic_operator: str = Form('gt'),
    generic_value: str = Form('0'),
):
    settings_map = {}
    if kind == 'generic_http':
        settings_map = {
            'path': generic_path,
            'field': generic_field,
            'operator': generic_operator,
            'value': generic_value,
        }
    try:
        integration_service.save(
            integration_id=None,
            name=name,
            kind=kind,
            container_name=container_name,
            base_url=base_url,
            permission_mode=permission_mode,
            credential=credential,
            settings=settings_map,
        )
    except Exception as exc:
        return RedirectResponse(f'/integrations?message={escape(str(exc))}', status_code=303)
    return RedirectResponse('/integrations?message=Integration%20saved', status_code=303)


@app.post('/integrations/{integration_id}/test')
def test_integration(integration_id: int):
    result = integration_service.test(integration_id)
    prefix = 'OK: ' if result.get('ok') else 'FAILED: '
    from urllib.parse import quote
    return RedirectResponse(f"/integrations?message={quote(prefix + result.get('message', 'unknown result'))}", status_code=303)


@app.post('/integrations/{integration_id}/delete')
def delete_integration(integration_id: int):
    integration_service.delete(integration_id)
    return RedirectResponse('/integrations?message=Integration%20deleted', status_code=303)


@app.get('/', response_class=HTMLResponse)
def dashboard():
    try:
        items = [enrich(item) for item in docker_service.containers()]
    except Exception as exc:
        return HTMLResponse(f'<h1>Kingdom Manager</h1><p>Docker unavailable: {escape(str(exc))}</p>', status_code=503)

    rows = []
    for item in items:
        c = item['classification']
        a = item['activity']
        d = item['interruption']
        rows.append(
            '<tr>'
            f"<td>{escape(str(item.get('name', 'unknown')))}</td>"
            f"<td>{escape(str(item.get('status', 'unknown')))}</td>"
            f"<td>{escape(str(item.get('health', 'none')))}</td>"
            f"<td class='image'>{escape(str(item.get('image', 'unknown')))}</td>"
            f"<td>{escape(str(c.get('category', 'unknown')))}</td>"
            f"<td>{escape(str(c.get('stack') or 'standalone'))}</td>"
            f"<td>{escape(str(a.get('state', 'unknown')))}</td>"
            f"<td><span class='decision {escape(str(d.get('decision', 'WAIT')).lower())}'>{escape(str(d.get('decision', 'WAIT')))}</span></td>"
            f"<td>{escape(str(a.get('reason', 'no reason available')))}</td>"
            '</tr>'
        )

    total = len(items)
    running = sum(1 for i in items if i.get('status') == 'running')
    safe = sum(1 for i in items if i.get('interruption', {}).get('safe'))
    integrations_count = len(integration_service.list())
    html = f'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kingdom Manager</title>
<style>
body{{font-family:system-ui;background:#11131a;color:#eee;margin:2rem}}h1{{margin-bottom:.25rem}}.sub{{color:#aaa;margin-top:0}}a{{color:#c6b7ff}}
.summary{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}.card{{background:#191c25;border:1px solid #2b3040;border-radius:.7rem;padding:.8rem 1rem}}
table{{border-collapse:collapse;width:100%;background:#191c25}}th,td{{padding:.65rem;border-bottom:1px solid #2b3040;text-align:left;font-size:.86rem;vertical-align:top}}th{{color:#c6b7ff;position:sticky;top:0;background:#191c25}}.image{{max-width:360px;word-break:break-word}}.decision{{padding:.2rem .45rem;border-radius:.35rem;background:#2b3040}}.safe{{background:#164e32}}.wait{{background:#5b4a12}}.locked{{background:#5a1d1d}}
</style></head><body>
<h1>👑 Kingdom Manager</h1><p class="sub">v0.3 · read-only integrations & policy mode</p>
<p><a href='/integrations'>🔌 Manage Integrations</a></p>
<div class="summary"><div class="card">Containers: <b>{total}</b></div><div class="card">Running: <b>{running}</b></div><div class="card">Safe now: <b>{safe}</b></div><div class="card">Integrations: <b>{integrations_count}</b></div></div>
<table><thead><tr><th>Container</th><th>Status</th><th>Health</th><th>Image</th><th>Class</th><th>Stack</th><th>Activity</th><th>Interrupt</th><th>Reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>'''
    return HTMLResponse(html)
