(() => {
  'use strict';
  const config = window.AIZHI_GITHUB;
  if (!config) return;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const root = `https://api.github.com/repos/${config.repository}`;
  const prefix = `aizhi-actions:${config.repository}:`;
  let token = '';
  let authorization;
  const jobs = new Map();
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const b64 = bytes => btoa(Array.from(bytes, value => String.fromCharCode(value)).join(''));
  const unb64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));

  async function api(path, options = {}) {
    if (!token) await authorize();
    const response = await fetch(root + path, {
      ...options,
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28', ...options.headers },
      signal: AbortSignal.timeout(25000)
    });
    if (response.status === 401) {
      token = '';
      throw new Error('GitHub 授权已失效，请重新连接后继续。');
    }
    if (response.status === 403) throw new Error('GitHub 权限不足或请求额度已用尽，请检查仓库的 Actions、Contents 权限。');
    return response;
  }

  function authorize() {
    if (authorization) return authorization;
    authorization = new Promise((resolve, reject) => {
      const panel = document.createElement('dialog');
      panel.style.cssText = 'max-width:460px;width:90%;padding:24px;border:1px solid #46575A;border-radius:8px;line-height:1.8;color:#1C2A2D;background:#F7F8F4';
      panel.innerHTML = '<form><h2 style="margin-top:0">连接 GitHub 验收环境</h2><p>使用有本仓库权限的 GitHub 账号创建细粒度访问令牌，仅授权本仓库：Actions 读写、Contents 读写。令牌仅保留在当前页面，刷新后需重新输入。</p><label>仓库访问令牌<input type="password" required autocomplete="off" style="display:block;width:100%;padding:10px;margin:8px 0 16px"></label><p role="status"></p><button type="button" data-cancel>取消</button> <button type="submit">连接并继续</button></form>';
      document.body.append(panel);
      const close = () => { panel.close(); panel.remove(); };
      const cancel = () => { close(); reject(new Error('尚未连接 GitHub，作答已保留。')); };
      panel.addEventListener('cancel', event => { event.preventDefault(); cancel(); });
      panel.querySelector('[data-cancel]').onclick = cancel;
      panel.querySelector('form').onsubmit = async event => {
        event.preventDefault();
        const input = panel.querySelector('input');
        const candidate = input.value.trim();
        const button = panel.querySelector('[type=submit]');
        button.disabled = true;
        try {
          const response = await fetch(root, { headers: { Authorization: `Bearer ${candidate}`, Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(20000) });
          if (!response.ok) throw new Error('无法访问仓库，请检查账号和令牌。');
          const repository = await response.json();
          if (!repository.permissions?.push) throw new Error('需要具有此仓库写入权限的账号。');
          token = candidate;
          input.value = '';
          close();
          resolve();
        } catch (error) {
          panel.querySelector('[role=status]').textContent = error.message;
          button.disabled = false;
        }
      };
      panel.showModal();
    }).finally(() => { authorization = null; });
    return authorization;
  }

  function status(message) {
    let banner = document.getElementById('github-status');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'github-status';
      banner.setAttribute('role', 'status');
      banner.style.cssText = 'position:fixed;bottom:8px;left:50%;transform:translateX(-50%);width:min(94%,560px);background:#1C2A2D;color:white;padding:10px 14px;border-radius:6px;z-index:65;font:13px/1.5 sans-serif';
      document.body.append(banner);
    }
    banner.textContent = message;
  }

  async function encryptRequest(value) {
    const resultKey = crypto.getRandomValues(new Uint8Array(32));
    const inputKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const publicKey = await crypto.subtle.importKey('spki', unb64(config.publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const plain = encoder.encode(JSON.stringify({ ...value, result_key: b64(resultKey) }));
    const compressed = new Uint8Array(await new Response(new Blob([plain]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, inputKey, compressed);
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, await crypto.subtle.exportKey('raw', inputKey));
    return { envelope: JSON.stringify({ key: b64(new Uint8Array(wrapped)), iv: b64(nonce), data: b64(new Uint8Array(ciphertext)) }), resultKey: b64(resultKey) };
  }

  async function read(job) {
    const response = await api(`/contents/jobs/${job.id}.json?ref=${config.resultBranch}&t=${Date.now()}`);
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('读取任务结果失败，请稍后继续。');
    const file = await response.json();
    const envelope = JSON.parse(decoder.decode(unb64(file.content.replace(/\s/g, ''))));
    const key = await crypto.subtle.importKey('raw', unb64(job.key), 'AES-GCM', false, ['decrypt']);
    const decoded = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv) }, key, unb64(envelope.data));
    const result = JSON.parse(decoder.decode(decoded));
    if (result.session && job.sessionId) localStorage.setItem(prefix + 'session:' + job.sessionId, JSON.stringify(result.session));
    return result;
  }

  async function launch(path, payload, onStart) {
    await authorizeIfNeeded();
    const id = crypto.randomUUID();
    const sessionId = payload.session_id || '';
    const session = sessionId ? JSON.parse(localStorage.getItem(prefix + 'session:' + sessionId) || '{}') : {};
    const encrypted = await encryptRequest({ path, payload, session });
    if (encoder.encode(encrypted.envelope).length > 60000) throw new Error('此次材料超出 GitHub 工作流输入上限，请缩短内容后重试。');
    const job = { id, key: encrypted.resultKey, sessionId, created: Date.now() };
    const response = await api(`/actions/workflows/diagnosis.yml/dispatches`, { method: 'POST', body: JSON.stringify({ ref: config.ref, inputs: { job_id: id, envelope: encrypted.envelope } }) });
    if (response.status !== 204) throw new Error('任务提交失败，请确认工作流已启用以及令牌拥有 Actions 读写权限。');
    localStorage.setItem(prefix + 'job:' + id, JSON.stringify(job));
    jobs.set(id, job);
    if (onStart) onStart(id);
    return job;
  }

  async function authorizeIfNeeded() { if (!token) await authorize(); }

  async function wait(path, payload, onProgress, deadlineMs, existingId, onStart) {
    await authorizeIfNeeded();
    let job = existingId && (jobs.get(existingId) || JSON.parse(localStorage.getItem(prefix + 'job:' + existingId) || 'null'));
    if (!job) job = await launch(path, typeof payload === 'function' ? payload() : payload, onStart);
    const deadline = Date.now() + Math.max(deadlineMs || 0, 30 * 60 * 1000);
    let lastRead = 0;
    let checks = 0;
    while (Date.now() < deadline) {
      status('GitHub 正在排队或处理任务，通常需要数分钟。作答已保存在本机。');
      try {
        const result = await read(job);
        lastRead = Date.now();
        if (result) {
          if (onProgress && (result.progress || result.base_result)) onProgress(result.progress, result);
          if (result.status === 'done') {
            status(result.result?.ok ? '本轮处理完成，可继续答题或查看报告。' : '本轮未完成，已保留作答，请查看提示。');
            return result.result;
          }
        }
        if (++checks % 5 === 0) {
          const runsResponse = await api('/actions/workflows/diagnosis.yml/runs?event=workflow_dispatch&per_page=30');
          if (runsResponse.ok) {
            const runs = await runsResponse.json();
            const run = runs.workflow_runs.find(item => item.display_title === `diagnosis-${job.id}`);
            if (run?.status === 'completed' && run.conclusion !== 'success') {
              const failure = new Error('GitHub 工作流已停止，请在仓库 Actions 中查看失败任务；作答已保存。');
              failure.terminal = true;
              throw failure;
            }
          }
        }
      } catch (error) {
        if (error.terminal || !token || /权限|额度/.test(error.message)) throw error;
        status('连接暂时中断，正在等待同一个任务恢复。');
      }
      if (!lastRead || Date.now() - lastRead > 60000) status('暂时无法读取 GitHub 任务，作答已保存，请检查网络。');
      await sleep(12000);
    }
    throw new Error('GitHub 任务仍在排队或尚未完成，进度已保存；请继续等待或在 Actions 页面检查任务。');
  }

  async function request(path, options = {}) {
    if (path.startsWith('/api/peer')) return new Response(JSON.stringify({ ok: true, total: 0 }), { status: 200 });
    if (path === '/api/track') {
      const payload = JSON.parse(options.body || '{}');
      if (payload.stage === 'consult') {
        const result = await wait(path, payload);
        if (!result.ok) throw new Error(result.msg || '联系请求未保存');
      }
      return new Response(JSON.stringify({ ok: true, local_only: payload.stage !== 'consult' }), { status: 200 });
    }
    if (path === '/api/score') {
      const result = await wait(path, JSON.parse(options.body || '{}'));
      return new Response(JSON.stringify(result), { status: 200 });
    }
    throw new Error('此接口尚未接入 GitHub 工作流。');
  }
  window.ActionsBridge = { wait, request, authorize };
})();
