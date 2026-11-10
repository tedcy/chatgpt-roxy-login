const $ = selector => document.querySelector(selector);
let settingsSchema = {}, proxyAccount = null, polling = false;
let workspaceCatalog = [], workspaceLoadGeneration = 0;
const stateLabels = {closed:'已关闭',queued:'排队中',failed:'失败',opening:'打开中',logging_in:'登录中',ready:'可操作',refreshing:'刷新中',waiting_user:'等待人工',closing:'关闭中',cleanup_failed:'清理待确认'};

async function api(path, options = {}) {
  const response = await fetch(path, {cache:'no-store', ...options,
    headers:options.body ? {'Content-Type':'application/json'} : undefined});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '请求失败');
  return data;
}
function notice(message, error = false) {
  const element = $('#notice');
  element.textContent = message; element.className = 'notice' + (error ? ' error' : ''); element.hidden = false;
}
function element(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = text;
  if (className) result.className = className;
  return result;
}
function date(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? '—' : parsed.toLocaleString();
}
async function loadSettings(keepWorkspaces = false) {
  workspaceLoadGeneration += 1;
  if (!keepWorkspaces) workspaceCatalog = [];
  const data = await api('/api/settings'); settingsSchema = data.schema;
  const fields = $('#settingsFields'); fields.replaceChildren();
  const groups = new Map();
  for (const [key, spec] of Object.entries(settingsSchema)) {
    if (!groups.has(spec.group)) {
      const group = element('fieldset', undefined, 'config-group');
      group.append(element('legend', spec.group));
      const grid = element('div', undefined, 'config-grid'); group.append(grid); fields.append(group); groups.set(spec.group, grid);
    }
    const wrapper = element('div', undefined, 'setting' + (['object','strings','delays'].includes(spec.kind) ? ' wide' : ''));
    const label = element('label', spec.label); label.htmlFor = key; wrapper.append(label);
    let control;
    const value = data.values[key] ?? spec.default;
    if (['ROXY_WORKSPACE_ID','ROXY_PROJECT_ID'].includes(key)) {
      control = element('select');
    } else if (['object','strings','delays'].includes(spec.kind)) {
      control = element('textarea'); control.value = JSON.stringify(value, null, 2); control.spellcheck = false;
    } else if (spec.choices) {
      control = element('select');
      for (const choice of spec.choices) { const option = element('option',choice); option.value = choice; control.append(option); }
      control.value = value;
    } else {
      control = element('input'); control.type = spec.kind === 'bool' ? 'checkbox' : spec.kind === 'secret' ? 'password' : ['int','float'].includes(spec.kind) ? 'number' : 'text';
      if (spec.kind === 'bool') control.checked = value;
      else if (spec.kind === 'secret') control.placeholder = data.api_token_set ? '已保存（遮罩）；留空保持原值，输入新值替换' : '尚未配置';
      else control.value = value;
      if (spec.minimum !== null) { control.min = spec.minimum; control.max = spec.maximum; control.step = spec.kind === 'int' ? '1' : 'any'; }
      control.autocomplete = 'off';
    }
    control.id = key; wrapper.append(control);
    wrapper.append(element('div', key + ' · 默认：' + JSON.stringify(spec.default), 'default'));
    if (data.effective && key in data.effective) wrapper.append(element('div','内核实际值：' + JSON.stringify(data.effective[key]),'default'));
    if (key === 'ROXY_API_TOKEN') wrapper.append(element('p','先登录 Roxy 客户端，在 API / Local API 设置中启用本地 API，复制 API Key 填入此处。已保存时可留空。','hint'));
    if (key === 'ROXY_API_BASE') wrapper.append(element('p','端口应与 Roxy 客户端 API 页一致；新版默认 50000。','hint'));
    groups.get(spec.group).append(wrapper);
  }
  const tools = element('div',undefined,'workspace-tools wide');
  const buttons = element('div',undefined,'workspace-buttons');
  const loadButton = element('button','获取团队/项目','secondary'); loadButton.id = 'loadWorkspaces';
  const saveButton = element('button','保存选择'); saveButton.id = 'saveWorkspaceSelection';
  buttons.append(loadButton,saveButton); tools.append(buttons);
  const status = element('p','填写连接信息后获取列表；选择团队和项目，再保存。','hint'); status.id = 'workspaceStatus'; tools.append(status);
  groups.get('Roxy 连接').append(tools);
  renderWorkspaceOptions(data.values.ROXY_WORKSPACE_ID,data.values.ROXY_PROJECT_ID);
  loadButton.addEventListener('click',loadWorkspaces);
  saveButton.addEventListener('click',saveSettings);
  $('#ROXY_WORKSPACE_ID').addEventListener('change',() => {
    renderWorkspaceOptions($('#ROXY_WORKSPACE_ID').value,'');
    const workspace = workspaceCatalog.find(item => item.id === $('#ROXY_WORKSPACE_ID').value);
    $('#workspaceStatus').textContent = workspace && !workspace.projects.length ? '该团队暂无项目，请先在 Roxy 中创建项目，再重新获取。' : '请选择此团队下的项目，再点击保存选择。';
  });
  $('#ROXY_PROJECT_ID').addEventListener('change',updateWorkspaceSaveButton);
  for (const key of ['ROXY_API_BASE','ROXY_API_TOKEN','ROXY_WORKSPACE_LIST_PATH','ROXY_WORKSPACE_LIST_METHOD']) {
    document.getElementById(key).addEventListener('input',invalidateWorkspaces);
    document.getElementById(key).addEventListener('change',invalidateWorkspaces);
  }
  const policies = $('#policies'); policies.replaceChildren();
  for (const [name,value] of Object.entries(data.policies)) policies.append(element('dt',name),element('dd',value));
  if (!data.api_token_set || !data.values.ROXY_WORKSPACE_ID || !data.values.ROXY_PROJECT_ID) $('#settingsPanel').hidden = false;
}
function workspaceOptions(control, items, selected, placeholder, savedLabel) {
  control.replaceChildren();
  const empty = element('option',placeholder); empty.value = ''; control.append(empty);
  for (const item of items) {
    const option = element('option',`${item.name}（${item.id}）`); option.value = item.id; control.append(option);
  }
  if (selected && !items.some(item => item.id === selected)) {
    const previous = element('option',`${savedLabel}（${selected}，请获取列表核对）`); previous.value = selected; control.append(previous);
  }
  control.value = selected || '';
}
function renderWorkspaceOptions(workspaceId = '', projectId = '') {
  workspaceOptions($('#ROXY_WORKSPACE_ID'),workspaceCatalog,workspaceId,'请选择团队','已保存团队');
  const workspace = workspaceCatalog.find(item => item.id === workspaceId);
  const projects = workspace?.projects || [];
  workspaceOptions($('#ROXY_PROJECT_ID'),projects,projectId,'请选择项目','已保存项目');
  $('#ROXY_PROJECT_ID').disabled = !projects.length;
  updateWorkspaceSaveButton();
}
function updateWorkspaceSaveButton() {
  const workspace = workspaceCatalog.find(item => item.id === $('#ROXY_WORKSPACE_ID').value);
  $('#saveWorkspaceSelection').disabled = !workspace?.projects.some(item => item.id === $('#ROXY_PROJECT_ID').value);
}
function invalidateWorkspaces() {
  workspaceLoadGeneration += 1; workspaceCatalog = [];
  renderWorkspaceOptions();
  $('#workspaceStatus').textContent = '连接信息已改变，请重新获取团队/项目。';
  $('#loadWorkspaces').disabled = false; $('#loadWorkspaces').textContent = '获取团队/项目';
}
function readSettingsForm() {
  const values = {};
  for (const [key,spec] of Object.entries(settingsSchema)) {
      const control = document.getElementById(key);
      if (spec.kind === 'bool') values[key] = control.checked;
      else if (['object','strings','delays'].includes(spec.kind)) {
        try { values[key] = JSON.parse(control.value); } catch { throw new Error(spec.label + '：JSON 格式无效'); }
      } else if (['float','int'].includes(spec.kind)) {
        if (!control.value.trim()) throw new Error(spec.label + '：不能为空');
        values[key] = Number(control.value);
      } else values[key] = control.value;
  }
  return values;
}
async function loadWorkspaces() {
  const generation = ++workspaceLoadGeneration;
  const button = $('#loadWorkspaces'); button.disabled = true; button.textContent = '获取中…';
  $('#workspaceStatus').textContent = '正在连接 Roxy 客户端…';
  try {
    const selectedWorkspace = $('#ROXY_WORKSPACE_ID').value, selectedProject = $('#ROXY_PROJECT_ID').value;
    const result = await api('/api/roxy/workspaces',{method:'POST',body:JSON.stringify(readSettingsForm())});
    if (generation !== workspaceLoadGeneration) return;
    workspaceCatalog = result.workspaces;
    renderWorkspaceOptions(selectedWorkspace,selectedProject);
    const projects = workspaceCatalog.reduce((count,item) => count + item.projects.length,0);
    $('#workspaceStatus').textContent = workspaceCatalog.length ? `已获取 ${workspaceCatalog.length} 个团队、${projects} 个项目；选择后点击“保存选择”。` : '未发现团队，请确认 Roxy 已登录并已有团队及项目。';
    notice(workspaceCatalog.length ? '已连接 Roxy 并获取团队/项目，请选择后保存。' : 'Roxy 连接成功，尚未发现团队。');
  } catch(error) {
    if (generation === workspaceLoadGeneration) {
      $('#workspaceStatus').textContent = error.message; notice(error.message,true);
    }
  } finally {
    if (generation === workspaceLoadGeneration) { button.disabled = false; button.textContent = '获取团队/项目'; }
  }
}
async function saveSettings() {
  try {
    const values = readSettingsForm();
    const result = await api('/api/settings', {method:'PUT', body:JSON.stringify(values)});
    await loadSettings(true); notice(result.message);
  } catch(error) { notice(error.message,true); }
}
function button(text, callback, disabled, className = 'secondary') {
  const result = element('button',text,className); result.disabled = disabled;
  result.addEventListener('click', async () => {
    result.disabled = true;
    try { await callback(); } catch(error) { notice(error.message,true); }
    finally { await loadAccounts().catch(error => notice(error.message,true)); }
  });
  return result;
}
async function action(account, name) {
  await api(`/api/accounts/${account.id}/${name}`, {method:'POST', body:'{}'});
  notice(name === 'close' ? '已请求保存并关闭窗口' : '已开始浏览器操作');
}
async function editProxy(account) {
  const data = await api(`/api/accounts/${account.id}/proxy`);
  proxyAccount = account; $('#proxyEmail').textContent = account.email;
  $('#showProxy').checked = false; $('#proxyValue').type = 'password'; $('#proxyValue').value = data.proxy;
  $('#proxyDialog').showModal();
}
async function copyToken(account) {
  // Obtain a value only on this user action. Never store tokens in a UI list/cache.
  const result = await api(`/api/accounts/${account.id}/token`);
  try { await navigator.clipboard.writeText(result.token); }
  catch {
    const area = element('textarea'); area.value = result.token;
    area.style.cssText = 'position:fixed;opacity:0'; document.body.append(area); area.select();
    const copied = document.execCommand('copy'); area.remove();
    if (!copied) throw new Error('剪贴板不可用，请允许本地网页使用剪贴板');
  }
  result.token = ''; notice('Token 已复制');
}
async function loadAccounts() {
  if (polling) return;
  polling = true;
  try {
    const {accounts} = await api('/api/accounts');
    $('#accountCount').textContent = accounts.length; $('#emptyAccounts').hidden = accounts.length > 0;
    const tbody = $('#accountRows'); tbody.replaceChildren();
    for (const account of accounts) {
      const row = element('tr'), identity = element('td'), session = element('td'), state = element('td'), operations = element('td');
      identity.append(element('div',account.email,'email'),element('div',account.has_proxy ? '代理已配置' : '代理未配置','meta'));
      session.append(element('div',account.has_session ? '会话已保存' : '尚无会话'),element('div','保存：' + date(account.saved_at),'meta'));
      if (account.expires) session.append(element('div','有效期：' + date(account.expires),'meta'));
      state.append(element('span',stateLabels[account.state] || account.state,'badge ' + account.state),element('div',account.message || '—','meta'));
      const actions = element('div',undefined,'actions');
      const closed = account.state === 'closed', reusable = ['ready','waiting_user'].includes(account.state);
      actions.append(button('代理',() => editProxy(account),!closed),
        button('打开',() => action(account,'open'),!closed || !account.has_proxy,''),
        button('刷新会话',() => action(account,'refresh'),(!closed && !reusable) || !account.has_proxy),
        button(account.state === 'cleanup_failed' ? '重试清理' : '关闭窗口',() => action(account,'close'),closed || account.state === 'closing','danger'),
        button('复制 Token',() => copyToken(account),!account.has_token));
      operations.append(actions); row.append(identity,session,state,operations); tbody.append(row);
    }
  } finally { polling = false; }
}
$('#settingsToggle').addEventListener('click',() => { $('#settingsPanel').hidden = !$('#settingsPanel').hidden; });
$('#saveSettings').addEventListener('click',saveSettings);
$('#reloadAccounts').addEventListener('click',() => loadAccounts().catch(error => notice(error.message,true)));
$('#importFile').addEventListener('change',async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 2 * 1024 * 1024) { notice('TXT 不能超过 2 MB',true); return; }
  $('#importText').value = await file.text(); event.target.value = '';
});
$('#importAccounts').addEventListener('click',async () => {
  const control = $('#importAccounts'); control.disabled = true;
  try {
    const result = await api('/api/accounts/import',{method:'POST',body:JSON.stringify({text:$('#importText').value})});
    $('#importText').value = ''; notice(`已新增 ${result.added} 个，更新 ${result.updated} 个账号`); await loadAccounts();
  } catch(error) { notice(error.message,true); }
  finally { control.disabled = false; }
});
$('#showProxy').addEventListener('change',event => { $('#proxyValue').type = event.target.checked ? 'text' : 'password'; });
$('#cancelProxy').addEventListener('click',() => $('#proxyDialog').close());
$('#proxyDialog').addEventListener('close',() => { $('#proxyValue').value = ''; proxyAccount = null; });
$('#proxyForm').addEventListener('submit',async event => {
  event.preventDefault();
  try {
    await api(`/api/accounts/${proxyAccount.id}/proxy`,{method:'PUT',body:JSON.stringify({proxy:$('#proxyValue').value})});
    $('#proxyDialog').close(); notice('账号代理已保存'); await loadAccounts();
  } catch(error) { notice(error.message,true); }
});
Promise.all([loadSettings(),loadAccounts()]).catch(error => notice(error.message,true));
setInterval(() => loadAccounts().catch(error => notice(error.message,true)),2000);
