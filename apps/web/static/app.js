const $ = id => document.getElementById(id);
const token = () => $('token').value.trim();
const headers = () => token() ? {Authorization: 'Bearer ' + token(), 'Content-Type': 'application/json'} : {'Content-Type': 'application/json'};
async function api(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: headers()});
  if (!r.ok) throw new Error(r.status + ' ' + (await r.text()).slice(0, 300));
  return r.json();
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const show = (id, obj) => { $(id).textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); };

document.querySelectorAll('#tabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('#tabs button').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); $('tab-' + b.dataset.tab).classList.add('active');
});

async function refreshStats() {
  try {
    const h = await api('/api/health');
    $('health').textContent = '● online'; $('health').classList.add('ok');
    $('foot-status').textContent = 'providers: ' + h.providers.join(', ');
    $('stat-providers').textContent = h.providers.length;
    const tasks = await api('/api/tasks');
    $('stat-tasks').textContent = tasks.length;
    $('stat-tasks-sub').textContent = tasks.filter(t => t.status === 'completed').length + ' completed';
    const conns = await api('/api/connectors');
    $('stat-connectors').textContent = conns.length;
    $('stat-connectors-sub').textContent = conns.filter(c => c.mode === 'live').length + ' live · ' + conns.filter(c => c.mode === 'mock').length + ' mock';
    const docs = await api('/api/knowledge/documents');
    $('stat-docs').textContent = docs.length;
    renderTasks(tasks); renderConnectors(conns); renderDocs(docs);
  } catch (e) { $('health').textContent = '● offline: ' + e.message; }
}
function renderTasks(tasks) {
  const html = tasks.slice(0, 10).map(t =>
    `<div class="item"><b>${esc(t.title)}</b> <span class="badge">${esc(t.status)}</span>
     <div class="meta">${esc(t.id)} · ${esc(t.kind)} · model: ${esc(t.model_used || '—')} · $${(t.cost_usd||0).toFixed(4)}</div>
     ${t.result ? `<div>${esc(t.result.slice(0, 300))}</div>` : ''}
     ${t.error ? `<div style="color:var(--bad)">${esc(t.error)}</div>` : ''}</div>`).join('');
  $('recent-tasks').innerHTML = html || '<div class="item">No tasks yet.</div>';
  $('task-list').innerHTML = tasks.map(t =>
    `<div class="item"><b>${esc(t.title)}</b> <span class="badge">${esc(t.status)}</span>
     <div class="meta">${esc(t.id)} · autonomy L${t.autonomy_level} · ${new Date(t.created_at*1000).toLocaleString()}</div>
     ${t.plan ? `<div class="meta">Plan: ${esc(t.plan.summary)}</div>` : ''}
     ${t.verification ? `<div class="meta">Verification: ${esc(t.verification.verdict.slice(0,200))}</div>` : ''}</div>`).join('') || '<div class="item">No tasks yet.</div>';
}
function renderConnectors(conns) {
  $('connector-list').innerHTML = conns.map(c =>
    `<div class="item"><b>${esc(c.display_name)}</b> <span class="badge ${esc(c.mode)}">${esc(c.mode)}</span>
     <div class="meta">${esc(c.auth)} · ${esc(c.detail)}</div>
     <div class="meta">Capabilities: ${esc(c.capabilities.join(', '))}</div></div>`).join('');
}
function renderDocs(docs) {
  $('doc-list').innerHTML = docs.map(d =>
    `<div class="item"><b>${esc(d.title)}</b><div class="meta">${esc(d.source)} · ${esc(d.license)} · hash ${esc(d.hash.slice(0,12))}</div></div>`).join('') || '<div class="item">No documents yet.</div>';
}
async function refreshAgents() {
  const agents = await api('/api/agents');
  $('agent-list').innerHTML = agents.map(a => `<div class="item"><b>${esc(a.name)}</b><div class="meta">${esc(a.role)}</div></div>`).join('');
}
async function refreshModels() {
  const m = await api('/api/models');
  $('model-list').innerHTML = m.registry.map(e =>
    `<div class="item"><b>${esc(e.display_name)}</b> <span class="badge">${esc(e.provider)}</span>
     <div class="meta">quality ${e.quality} · $${e.cost_per_1m_in}/$${e.cost_per_1m_out} per 1M · ctx ${e.context.toLocaleString()} · ${esc(e.latency_tier)}${e.open_weight ? ' · open-weight ' + esc(e.license) : ''}</div></div>`).join('');
}
async function refreshAudit() {
  const log = await api('/api/audit');
  $('audit-list').innerHTML = log.map(a =>
    `<div class="item">${esc(a.action)} <div class="meta">${esc(a.actor)} · ${esc(a.detail)} · ${new Date(a.ts*1000).toLocaleString()}</div></div>`).join('') || '<div class="item">No audit entries yet.</div>';
}

$('task-submit').onclick = async () => {
  show('task-result', 'Submitting…');
  try {
    const r = await api('/api/tasks', {method: 'POST', body: JSON.stringify({instruction: $('task-input').value, autonomy_level: +$('task-level').value})});
    show('task-result', 'Task queued: ' + r.id + '\nInjection flags: ' + JSON.stringify(r.injection_flags) + '\nPolling for completion…');
    for (let i = 0; i < 30; i++) {
      await new Promise(res => setTimeout(res, 1000));
      const t = await api('/api/tasks/' + r.id);
      if (['completed', 'failed'].includes(t.status)) { show('task-result', t); refreshStats(); return; }
    }
    show('task-result', 'Still running — check the Tasks tab.');
  } catch (e) { show('task-result', 'Error: ' + e.message); }
};
$('refresh-tasks').onclick = refreshStats;
$('route-preview').onclick = async () => show('route-output', await api('/api/models/route?kind=' + $('route-kind').value));
$('doc-submit').onclick = async () => {
  try { show('doc-result', await api('/api/knowledge/documents', {method: 'POST', body: JSON.stringify({title: $('doc-title').value, content: $('doc-content').value})})); refreshStats(); }
  catch (e) { show('doc-result', 'Error: ' + e.message); }
};
$('search-btn').onclick = async () => {
  try { show('search-output', await api('/api/knowledge/search?q=' + encodeURIComponent($('search-q').value))); }
  catch (e) { show('search-output', 'Error: ' + e.message); }
};
$('wf-inbox').onclick = async () => { show('wf-inbox-out', 'Running…'); try { show('wf-inbox-out', await api('/api/workflows/inbox', {method: 'POST'})); } catch (e) { show('wf-inbox-out', 'Error: ' + e.message); } };
$('wf-meeting').onclick = async () => { show('wf-meeting-out', 'Running…'); try { show('wf-meeting-out', await api('/api/workflows/meeting', {method: 'POST', body: JSON.stringify({attendee: $('meet-attendee').value || 'professor@example.edu'})})); } catch (e) { show('wf-meeting-out', 'Error: ' + e.message); } };
$('wf-research').onclick = async () => { show('wf-research-out', 'Fetching…'); try { show('wf-research-out', await api('/api/workflows/research', {method: 'POST', body: JSON.stringify({url: $('research-url').value})})); refreshStats(); } catch (e) { show('wf-research-out', 'Error: ' + e.message); } };
$('wf-telegram').onclick = async () => { show('wf-telegram-out', 'Sending…'); try { show('wf-telegram-out', await api('/api/workflows/telegram', {method: 'POST', body: JSON.stringify({text: $('tg-text').value || 'status'})})); } catch (e) { show('wf-telegram-out', 'Error: ' + e.message); } };
$('code-run').onclick = async () => { show('code-out', 'Running…'); try { show('code-out', await api('/api/execute/python', {method: 'POST', body: JSON.stringify({code: $('code-input').value})})); } catch (e) { show('code-out', 'Error: ' + e.message); } };
$('refresh-audit').onclick = refreshAudit;

refreshStats(); refreshAgents(); refreshModels(); refreshAudit();
setInterval(refreshStats, 15000);
