const $ = (id) => document.getElementById(id);

let encryptItems = [];
let decryptItems = [];
let toastTimer = null;
let operationState = null;
let elevationContext = null;

function formatBytes(bytes) {
  if (bytes == null || Number.isNaN(Number(bytes))) return '—';
  const value = Number(bytes);
  if (value === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))}s`;
  const min = Math.floor(seconds / 60);
  const sec = Math.round(seconds % 60);
  if (min < 60) return `${min}m ${sec}s`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

function baseName(p) {
  return String(p).replace(/[/\\]+$/, '').split(/[/\\]/).pop();
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[ch]));
}

function showToast(title, text, mode = 'loading', sticky = false) {
  clearTimeout(toastTimer);
  const toast = $('toast');
  toast.className = `toast show ${mode}`;
  $('toastTitle').textContent = title;
  $('toastText').textContent = text;
  if (!sticky) toastTimer = setTimeout(() => toast.classList.remove('show'), 4500);
}

function setBusy(on) {
  document.body.classList.toggle('busy', on);
}

function setProgress(fraction) {
  const bar = $('progressBar');
  const fill = $('progressFill');
  if (fraction == null) {
    bar.classList.remove('show');
    fill.style.width = '0%';
    return;
  }
  bar.classList.add('show');
  fill.style.width = `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%`;
}

const STAGE_LABELS = {
  kdf: 'Derivando chave com Argon2id', pack: 'Preparando pasta', pack_verify: 'Validando pacote da pasta', encrypt: 'Criptografando chunks', verify: 'Verificando round-trip',
  decrypt: 'Descriptografando chunks', extract: 'Restaurando pasta', shred: 'Sobrescrevendo original', done: 'Finalizando'
};

function beginOperation(action, count, cancellable) {
  operationState = { action, stage: null, itemName: '', lastProcessed: 0, lastAt: performance.now(), speed: 0 };
  $('operationPanel').hidden = false;
  $('operationTitle').textContent = action === 'encrypt' ? 'Preparando criptografia…' : 'Preparando restauração…';
  $('operationStage').textContent = 'Preparando';
  $('operationPercent').textContent = '0%';
  $('operationFill').style.width = '0%';
  $('operationBytes').textContent = 'Aguardando dados';
  $('operationSpeed').textContent = 'Velocidade —';
  $('operationEta').textContent = 'ETA —';
  $('operationItems').textContent = `Item 1 de ${count}`;
  $('cancelOperation').disabled = !cancellable;
  $('cancelOperation').textContent = cancellable ? 'Cancelar com segurança' : 'Cancelamento indisponível';
  $('cancelHint').textContent = cancellable
    ? 'O cancelamento é cooperativo e remove resultados temporários antes de encerrar.'
    : 'No modo extremo, o cancelamento fica desativado para não interromper uma sobrescrita destrutiva.';
}

function endOperation() {
  operationState = null;
  $('operationPanel').hidden = true;
  setProgress(null);
}

function updateOperation(data) {
  if (!operationState) return;
  const now = performance.now();
  const processed = Number(data.processed || 0);
  const total = Number(data.totalBytes || 0);
  const stage = data.stage || 'done';
  const stageChanged = operationState.stage !== stage || operationState.itemName !== data.itemName;

  if (stageChanged) {
    operationState.stage = stage;
    operationState.itemName = data.itemName || '';
    operationState.lastProcessed = processed;
    operationState.lastAt = now;
    operationState.speed = 0;
  } else {
    const dt = (now - operationState.lastAt) / 1000;
    const delta = processed - operationState.lastProcessed;
    if (dt >= 0.15 && delta >= 0) {
      const instant = delta / dt;
      operationState.speed = operationState.speed ? operationState.speed * 0.7 + instant * 0.3 : instant;
      operationState.lastAt = now;
      operationState.lastProcessed = processed;
    }
  }

  const itemFraction = total > 0 ? Math.min(1, processed / total) : Number(data.itemFraction || 0);
  $('operationStage').textContent = STAGE_LABELS[stage] || 'Processando';
  $('operationTitle').textContent = data.itemName || 'Processando item';
  $('operationPercent').textContent = total > 0 ? `${Math.round(itemFraction * 100)}%` : '—%';
  $('operationFill').style.width = total > 0 ? `${Math.round(itemFraction * 100)}%` : '18%';
  $('operationBytes').textContent = total > 0 ? `${formatBytes(processed)} de ${formatBytes(total)}` : `${formatBytes(processed)} processados`;
  $('operationSpeed').textContent = operationState.speed > 0 ? `${formatBytes(operationState.speed)}/s` : 'Velocidade —';
  const eta = total > 0 && operationState.speed > 0 ? (total - processed) / operationState.speed : NaN;
  $('operationEta').textContent = `ETA ${formatDuration(eta)}`;
  $('operationItems').textContent = `Item ${Math.min((data.index ?? 0) + 1, data.totalItems || 1)} de ${data.totalItems || 1}`;
  $('cancelOperation').disabled = !data.cancellable || $('cancelOperation').dataset.requested === '1';
  setProgress(typeof data.fraction === 'number' ? data.fraction : 0);
}

function confirmAction(title, text) {
  return new Promise((resolve) => {
    const dialog = $('confirmDialog');
    $('confirmTitle').textContent = title;
    $('confirmText').textContent = text;
    const onClose = () => { dialog.removeEventListener('close', onClose); resolve(dialog.returnValue === 'confirm'); };
    dialog.addEventListener('close', onClose);
    dialog.showModal();
  });
}

function showResult(title, text, ok = true) {
  $('resultTitle').textContent = title;
  $('resultText').textContent = text;
  $('resultIcon').textContent = ok ? '✓' : '!';
  $('resultIcon').classList.toggle('fail', !ok);
  $('resultDialog').showModal();
}

function navigateTo(viewId) {
  document.querySelectorAll('.nav,.view').forEach((x) => x.classList.remove('active'));
  const nav = document.querySelector(`.nav[data-view="${viewId}"]`);
  if (nav) nav.classList.add('active');
  const view = $(viewId);
  if (view) view.classList.add('active');
  if (viewId === 'activity') renderActivity();
}

async function offerElevation(action, failures) {
  const first = failures?.[0];
  if (!first) return false;
  let info = null;
  try { info = await window.cryptoGuard.getAppInfo(); } catch { /* usa fallback abaixo */ }

  if (info?.platform !== 'win32') {
    showResult('Acesso negado', 'O sistema operacional negou acesso ao item selecionado. Ajuste as permissões do arquivo ou pasta e tente novamente.', false);
    return true;
  }
  if (info?.elevated) {
    const denied = first.permissionPath || first.path;
    showResult(
      'Acesso continua bloqueado',
      `O Crypto Guard já está executando como administrador, mas o Windows ainda negou acesso${denied ? ` a “${denied}”` : ''}. Isso pode indicar uma regra explícita de ACL, proteção do OneDrive/Windows Defender ou outro bloqueio do sistema.`,
      false
    );
    return true;
  }

  elevationContext = {
    action,
    paths: failures.map((item) => item.path).filter(Boolean),
  };
  const denied = first.permissionPath || first.path || '';
  $('elevationText').textContent = action === 'encrypt'
    ? 'O Windows negou acesso a um item durante a criptografia. O Crypto Guard pode reiniciar como administrador e tentar novamente com os itens que falharam.'
    : 'O Windows negou acesso durante a restauração. O Crypto Guard pode reiniciar como administrador e tentar novamente.';
  if (denied) {
    $('elevationPath').hidden = false;
    $('elevationPath').textContent = denied;
  } else {
    $('elevationPath').hidden = true;
    $('elevationPath').textContent = '';
  }
  $('requestElevation').disabled = false;
  $('requestElevation').textContent = 'Solicitar permissão do Windows';
  $('elevationDialog').showModal();
  return true;
}

$('cancelElevation').onclick = () => {
  elevationContext = null;
  if ($('elevationDialog').open) $('elevationDialog').close();
};

$('requestElevation').onclick = async () => {
  if (!elevationContext) return;
  const button = $('requestElevation');
  button.disabled = true;
  button.textContent = 'Aguardando o Windows…';
  localStorage.setItem('cryptoGuardPendingElevation', JSON.stringify({
    action: elevationContext.action,
    paths: elevationContext.paths,
    at: Date.now()
  }));
  try {
    const result = await window.cryptoGuard.requestElevation();
    if (!result?.ok) {
      localStorage.removeItem('cryptoGuardPendingElevation');
      button.disabled = false;
      button.textContent = 'Solicitar permissão do Windows';
      const message = result?.cancelled
        ? 'A solicitação foi cancelada no controle de conta do Windows.'
        : (result?.reason || 'O Windows não concedeu a permissão administrativa.');
      showToast('Permissão não concedida', message, 'error');
    } else if (result.alreadyElevated) {
      localStorage.removeItem('cryptoGuardPendingElevation');
      button.disabled = false;
      button.textContent = 'Solicitar permissão do Windows';
      showToast('Já está elevado', 'O Crypto Guard já está executando como administrador.', 'error');
    }
  } catch (err) {
    localStorage.removeItem('cryptoGuardPendingElevation');
    button.disabled = false;
    button.textContent = 'Solicitar permissão do Windows';
    showToast('Falha ao solicitar permissão', err.message, 'error');
  }
};

// Navegação
for (const btn of document.querySelectorAll('.nav')) {
  btn.addEventListener('click', () => navigateTo(btn.dataset.view));
}

for (const btn of document.querySelectorAll('.peek')) {
  btn.addEventListener('click', () => {
    const input = $(btn.dataset.target);
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? 'Mostrar' : 'Ocultar';
  });
}

function renderSelectionList(containerId, items, onRemove) {
  const container = $(containerId);
  if (!items.length) {
    container.classList.add('empty');
    container.innerHTML = '<p class="selection-empty-text">Nenhum item selecionado ainda.</p>';
    return;
  }
  container.classList.remove('empty');
  container.innerHTML = items.map((item, idx) => `
    <div class="selection-item">
      <span class="sel-ico">${item.isDirectory ? '📁' : '📄'}</span>
      <div class="sel-info"><div class="sel-name">${escapeHtml(item.name)}</div><div class="sel-meta">${item.isDirectory ? 'Pasta' : escapeHtml(formatBytes(item.size))}</div></div>
      <button type="button" class="sel-remove" data-idx="${idx}" title="Remover">✕</button>
    </div>`).join('');
  container.querySelectorAll('.sel-remove').forEach((btn) => btn.addEventListener('click', () => onRemove(Number(btn.dataset.idx))));
}

function addEncryptItems(infos) {
  const existing = new Set(encryptItems.map((i) => i.path));
  for (const info of infos || []) if (info?.path && !existing.has(info.path)) { encryptItems.push(info); existing.add(info.path); }
  wireEncryptRemoval();
}
function wireEncryptRemoval() { renderSelectionList('encryptList', encryptItems, (idx) => { encryptItems.splice(idx, 1); wireEncryptRemoval(); }); }

function isEncryptedName(name) { return /\.cguard$/i.test(String(name || '')); }
function addDecryptItems(infos) {
  const existing = new Set(decryptItems.map((i) => i.path));
  for (const info of infos || []) if (info?.path && isEncryptedName(info.name) && !existing.has(info.path)) { decryptItems.push(info); existing.add(info.path); }
  wireDecryptRemoval();
}
function wireDecryptRemoval() { renderSelectionList('decryptList', decryptItems, (idx) => { decryptItems.splice(idx, 1); wireDecryptRemoval(); }); }

function handleExternalEncryptedFiles(infos) {
  const valid = Array.isArray(infos) ? infos.filter((item) => item?.path && isEncryptedName(item.name || item.path)) : [];
  if (!valid.length) return;
  addDecryptItems(valid);
  navigateTo('decrypt');
  requestAnimationFrame(() => {
    if ($('decPassword') && !$('welcomeDialog')?.open) $('decPassword').focus();
  });
  showToast(
    'Arquivo Crypto Guard aberto',
    valid.length === 1 ? `${valid[0].name || baseName(valid[0].path)} pronto para descriptografar.` : `${valid.length} arquivos .cguard prontos para descriptografar.`,
    'success'
  );
}

$('pickFiles').onclick = async () => addEncryptItems(await window.cryptoGuard.pickFiles());
$('pickFolder').onclick = async () => { const info = await window.cryptoGuard.pickFolder(); if (info) addEncryptItems([info]); };
$('pickEncrypted').onclick = async () => addDecryptItems(await window.cryptoGuard.pickEncryptedFiles());

function wireDropZone(zoneId, onDrop) {
  const zone = $(zoneId);
  ['dragenter', 'dragover'].forEach((evt) => zone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); zone.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((evt) => zone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); zone.classList.remove('dragover'); }));
  zone.addEventListener('drop', async (e) => {
    const paths = Array.from(e.dataTransfer.files).map((f) => window.cryptoGuard.getPathForFile(f)).filter(Boolean);
    if (paths.length) onDrop(await window.cryptoGuard.pathsInfo(paths));
  });
}
wireDropZone('encDropZone', addEncryptItems);
wireDropZone('decDropZone', addDecryptItems);

function passwordScore(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 4);
}
const STRENGTH_LABELS = ['Muito fraca', 'Fraca', 'Razoável', 'Boa', 'Forte'];
const STRENGTH_COLORS = ['#ef5b78', '#ef5b78', '#f2b34b', '#42c99a', '#42c99a'];
$('encPassword').addEventListener('input', (e) => {
  const score = passwordScore(e.target.value);
  $('strengthFill').style.width = e.target.value ? `${(score / 4) * 100}%` : '0%';
  $('strengthFill').style.background = STRENGTH_COLORS[score];
  $('strengthLabel').textContent = e.target.value ? STRENGTH_LABELS[score] : '';
});

function loadActivity() { try { return JSON.parse(localStorage.getItem('cryptoGuardActivity') || '[]'); } catch { return []; } }
function saveActivity(list) { localStorage.setItem('cryptoGuardActivity', JSON.stringify(list.slice(0, 30))); }
function pushActivity(entry) { const list = loadActivity(); list.unshift({ ...entry, at: Date.now() }); saveActivity(list); }
function renderActivity() {
  const list = loadActivity();
  const container = $('activityList');
  if (!list.length) { container.innerHTML = '<p class="selection-empty-text">Nenhuma atividade ainda.</p>'; return; }
  container.innerHTML = list.map((item) => `
    <div class="activity-item ${item.ok ? 'ok' : 'fail'}"><div class="act-ico">${item.ok ? '✓' : '✕'}</div>
    <div class="act-info"><div class="act-name">${item.action === 'encrypt' ? 'Criptografado' : 'Descriptografado'}: ${escapeHtml(item.name)}</div>
    <div class="act-meta">${escapeHtml(new Date(item.at).toLocaleString('pt-BR'))}${item.error ? ` — ${escapeHtml(item.error)}` : ''}</div></div></div>`).join('');
}
$('clearActivity').onclick = () => { saveActivity([]); renderActivity(); };

window.cryptoGuard.onProgress(updateOperation);
$('cancelOperation').onclick = async () => {
  const btn = $('cancelOperation');
  btn.dataset.requested = '1';
  btn.disabled = true;
  btn.textContent = 'Solicitando cancelamento…';
  const result = await window.cryptoGuard.cancelCrypto();
  if (!result?.ok) {
    delete btn.dataset.requested;
    btn.disabled = false;
    btn.textContent = 'Cancelar com segurança';
    showToast('Não foi possível cancelar', result?.reason === 'unsafe-stage' ? 'O modo extremo não pode ser interrompido com segurança.' : 'A operação já pode ter terminado.', 'error');
  } else {
    $('cancelHint').textContent = 'Cancelamento solicitado. Aguardando um ponto seguro entre blocos…';
  }
};

$('advancedMode').onchange = () => { $('advancedDetails').hidden = !$('advancedMode').checked; };

$('encryptBtn').onclick = async () => {
  const password = $('encPassword').value;
  const confirm = $('encConfirm').value;
  const keepOriginal = $('keepOriginal').checked;
  const advancedMode = $('advancedMode').checked;
  const shredPasses = parseInt($('shredPasses').value, 10) || 2;
  if (!encryptItems.length) return showToast('Selecione um item', 'Escolha ao menos um arquivo ou pasta primeiro.', 'error');
  if (!password) return showToast('Senha obrigatória', 'Digite a senha desejada.', 'error');
  if (password !== confirm) return showToast('Senhas diferentes', 'A confirmação não corresponde à senha.', 'error');
  if (password.length < 12) return showToast('Senha muito curta', 'Use pelo menos 12 caracteres.', 'error');
  if (advancedMode && keepOriginal) return showToast('Combinação inválida', 'Desmarque “Manter o original” para usar o modo extremo.', 'error');

  if (advancedMode) {
    const ok = await confirmAction(
      'Ativar modo extremo?',
      `O contêiner CGUARD v4 será criado e verificado primeiro. Depois, o original será sobrescrito ${shredPasses} vez(es) antes de ser removido. Essa sobrescrita é best-effort e NÃO garante eliminação física em SSD/NVMe, snapshots, backups ou armazenamento sincronizado. Durante essa operação, o cancelamento ficará indisponível.`
    );
    if (!ok) return;
  }

  const paths = encryptItems.map((i) => i.path);
  try {
    setBusy(true); setProgress(0); beginOperation('encrypt', paths.length, !advancedMode);
    showToast('Crypto Guard', `Protegendo ${paths.length} ${paths.length === 1 ? 'item' : 'itens'}…`, 'loading', true);
    const { results, cancelled, requested } = await window.cryptoGuard.runCrypto({ action: 'encrypt', paths, password, keepOriginal, advancedMode, shredPasses });
    let okCount = 0;
    for (const r of results) { pushActivity({ action: 'encrypt', name: baseName(r.path), ok: r.ok, error: r.ok ? null : r.error }); if (r.ok) okCount++; }
    const permissionFailures = results.filter((r) => !r.ok && r.errorCode === 'permission_denied');
    if (cancelled) {
      showToast('Operação cancelada', `${okCount} item(ns) concluído(s) antes do cancelamento.`, 'error');
      showResult('Operação cancelada', 'O processamento foi interrompido em um ponto seguro. Resultados temporários da operação atual foram removidos.', false);
    } else if (permissionFailures.length) {
      showToast('Permissão necessária', 'O Windows bloqueou o acesso a pelo menos um item.', 'error');
      await offerElevation('encrypt', permissionFailures);
    } else if (okCount === requested) {
      showToast('Concluído', `${okCount} item(ns) protegido(s) com sucesso.`, 'success');
      showResult('Arquivos protegidos', `${okCount} de ${requested} item(ns) foram criptografados e verificados com sucesso.`);
      encryptItems = []; wireEncryptRemoval();
    } else {
      showToast('Concluído com falhas', `${okCount} de ${requested} item(ns) protegido(s).`, 'error');
      showResult('Alguns itens falharam', `${okCount} de ${requested} item(ns) foram concluídos. Consulte “Atividade recente” para os detalhes.`, false);
    }
    $('encPassword').value = ''; $('encConfirm').value = ''; $('strengthFill').style.width = '0%'; $('strengthLabel').textContent = '';
  } catch (err) {
    showToast('Falha na criptografia', err.message, 'error');
    showResult('Não foi possível concluir', err.message, false);
  } finally {
    delete $('cancelOperation').dataset.requested; setBusy(false); endOperation();
  }
};

$('decryptBtn').onclick = async () => {
  const password = $('decPassword').value;
  const keepEncrypted = $('keepEncrypted').checked;
  if (!decryptItems.length) return showToast('Selecione o arquivo', 'Escolha ao menos um arquivo .cguard v4.', 'error');
  if (!password) return showToast('Senha obrigatória', 'Digite a senha usada na criptografia.', 'error');
  const paths = decryptItems.map((i) => i.path);
  try {
    setBusy(true); setProgress(0); beginOperation('decrypt', paths.length, true);
    showToast('Crypto Guard', `Restaurando ${paths.length} ${paths.length === 1 ? 'item' : 'itens'}…`, 'loading', true);
    const { results, cancelled, requested } = await window.cryptoGuard.runCrypto({ action: 'decrypt', paths, password, keepEncrypted });
    let okCount = 0;
    for (const r of results) { pushActivity({ action: 'decrypt', name: baseName(r.path), ok: r.ok, error: r.ok ? null : r.error }); if (r.ok) okCount++; }
    const permissionFailures = results.filter((r) => !r.ok && r.errorCode === 'permission_denied');
    if (cancelled) {
      showToast('Operação cancelada', `${okCount} item(ns) concluído(s) antes do cancelamento.`, 'error');
      showResult('Operação cancelada', 'O arquivo criptografado foi preservado quando a restauração atual não chegou ao fim.', false);
    } else if (permissionFailures.length) {
      showToast('Permissão necessária', 'O Windows bloqueou o acesso a pelo menos um item.', 'error');
      await offerElevation('decrypt', permissionFailures);
    } else if (okCount === requested) {
      showToast('Restaurado', `${okCount} item(ns) restaurado(s) com sucesso.`, 'success');
      showResult('Conteúdo restaurado', `${okCount} de ${requested} item(ns) foram autenticados e restaurados com sucesso.`);
      decryptItems = []; wireDecryptRemoval();
    } else {
      showToast('Concluído com falhas', `${okCount} de ${requested} item(ns) restaurado(s).`, 'error');
      showResult('Alguns itens falharam', `${okCount} de ${requested} item(ns) foram concluídos. Consulte “Atividade recente” para os detalhes.`, false);
    }
    $('decPassword').value = '';
  } catch (err) {
    showToast('Não foi possível restaurar', err.message, 'error');
    showResult('Falha na restauração', err.message, false);
  } finally {
    delete $('cancelOperation').dataset.requested; setBusy(false); endOperation();
  }
};

let updateReadyToInstall = false;

function formatUpdateProgress(data) {
  const pct = Math.max(0, Math.min(100, Number(data?.percent || 0)));
  return `${pct.toFixed(pct >= 10 ? 0 : 1)}%`;
}

window.cryptoGuard.onUpdateStatus((data) => {
  const status = $('updateStatus');
  const button = $('checkUpdates');
  if (!status || !button || !data) return;
  switch (data.status) {
    case 'checking':
      updateReadyToInstall = false;
      status.textContent = 'Verificando…';
      button.textContent = 'Verificando…';
      button.disabled = true;
      break;
    case 'current':
      updateReadyToInstall = false;
      status.textContent = `Atualizado · v${data.version || 'atual'}`;
      button.textContent = 'Verificar atualização agora';
      button.disabled = false;
      break;
    case 'available':
      updateReadyToInstall = false;
      status.textContent = `v${data.version || 'nova'} encontrada · baixando`;
      button.textContent = 'Baixando atualização…';
      button.disabled = true;
      showToast('Atualização encontrada', `A versão ${data.version || 'mais recente'} será baixada automaticamente.`, 'loading', true);
      break;
    case 'downloading':
      updateReadyToInstall = false;
      status.textContent = `Baixando atualização · ${formatUpdateProgress(data)}`;
      button.textContent = `Baixando · ${formatUpdateProgress(data)}`;
      button.disabled = true;
      break;
    case 'downloaded':
      updateReadyToInstall = true;
      status.textContent = data.waitingForCrypto
        ? 'Atualização pronta · finalize a operação atual'
        : `Atualização pronta${data.version ? ` · v${data.version}` : ''}`;
      button.textContent = data.waitingForCrypto ? 'Aguardando operação terminar' : 'Instalar e reiniciar';
      button.disabled = !!data.waitingForCrypto;
      showToast(
        'Atualização pronta',
        data.waitingForCrypto
          ? 'Finalize a operação criptográfica atual; depois instale a atualização.'
          : 'Clique em “Instalar e reiniciar”. O instalador será exibido e o Crypto Guard reabrirá ao concluir.',
        'success',
        true
      );
      break;
    case 'installing':
      status.textContent = 'Instalando atualização…';
      button.textContent = 'Instalando…';
      button.disabled = true;
      showToast('Atualizando Crypto Guard', 'O aplicativo será fechado, o instalador será executado e o Crypto Guard deverá reabrir ao concluir.', 'loading', true);
      break;
    case 'error':
      updateReadyToInstall = false;
      status.textContent = data.message || 'Não foi possível verificar agora';
      button.textContent = 'Tentar novamente';
      button.disabled = false;
      break;
  }
});

$('checkUpdates').onclick = async () => {
  try {
    if (updateReadyToInstall) {
      const result = await window.cryptoGuard.installUpdate();
      if (!result?.ok && result?.reason === 'active-crypto-operation') {
        $('updateStatus').textContent = 'Atualização pronta · finalize a operação atual';
        $('checkUpdates').textContent = 'Aguardando operação terminar';
        $('checkUpdates').disabled = true;
      } else if (!result?.ok && result?.reason === 'no-downloaded-update') {
        updateReadyToInstall = false;
        $('checkUpdates').textContent = 'Verificar atualização agora';
        $('checkUpdates').disabled = false;
      }
      return;
    }

    $('updateStatus').textContent = 'Verificando…';
    const result = await window.cryptoGuard.checkForUpdates();
    if (!result?.ok && result?.reason === 'development') {
      $('updateStatus').textContent = 'Disponível somente no app instalado';
      $('checkUpdates').textContent = 'Verificar atualização agora';
      $('checkUpdates').disabled = false;
    } else if (!result?.ok && result?.reason === 'unsupported-session') {
      $('updateStatus').textContent = 'Verificação adiada nesta sessão';
      $('checkUpdates').textContent = 'Verificar atualização agora';
      $('checkUpdates').disabled = false;
    }
  } catch {
    $('updateStatus').textContent = 'Não foi possível verificar agora';
    $('checkUpdates').textContent = 'Tentar novamente';
    $('checkUpdates').disabled = false;
  }
};

window.cryptoGuard.getAppInfo().then((info) => {
  $('appVersion').textContent = info?.version || '—';
  if ($('privilegeStatus')) {
    $('privilegeStatus').textContent = info?.elevated ? 'Administrador · UAC ativo' : 'Modo padrão';
    $('privilegeStatus').classList.toggle('elevated', !!info?.elevated);
  }
}).catch(() => {});

async function restorePendingElevationSelection() {
  const raw = localStorage.getItem('cryptoGuardPendingElevation');
  if (!raw) return;
  try {
    const pending = JSON.parse(raw);
    if (!pending || !Array.isArray(pending.paths) || Date.now() - Number(pending.at || 0) > 10 * 60 * 1000) {
      localStorage.removeItem('cryptoGuardPendingElevation');
      return;
    }
    const info = await window.cryptoGuard.getAppInfo();
    if (!info?.elevated) return;
    const items = await window.cryptoGuard.pathsInfo(pending.paths);
    if (pending.action === 'decrypt') {
      addDecryptItems(items);
      navigateTo('decrypt');
    } else {
      addEncryptItems(items);
      navigateTo('encrypt');
    }
    localStorage.removeItem('cryptoGuardPendingElevation');
    showToast('Permissão administrativa ativa', 'Os itens bloqueados foram selecionados novamente. Digite a senha e tente outra vez.', 'success', true);
  } catch {
    localStorage.removeItem('cryptoGuardPendingElevation');
  }
}
restorePendingElevationSelection();

window.cryptoGuard.onOpenEncryptedFiles(handleExternalEncryptedFiles);
window.cryptoGuard.consumeOpenFiles().then(handleExternalEncryptedFiles).catch(() => {});

if (!localStorage.getItem('cryptoGuardOnboardingDone')) $('welcomeDialog').showModal();
$('finishWelcome').onclick = () => { localStorage.setItem('cryptoGuardOnboardingDone', '1'); $('welcomeDialog').close(); if (decryptItems.length) { navigateTo('decrypt'); $('decPassword')?.focus(); } };
