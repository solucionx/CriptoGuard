import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = path.resolve(import.meta.dirname, '..');
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));
const pkg = readJson('package.json');
const lock = readJson('package-lock.json');
const errors = [];

if (pkg.version !== lock.version || pkg.version !== lock.packages?.['']?.version) {
  errors.push('package.json e package-lock.json estão com versões diferentes.');
}
const winTargets = pkg.build?.win?.target ?? [];
if (!winTargets.some((item) => (typeof item === 'string' ? item : item?.target) === 'nsis')) {
  errors.push('Target NSIS ausente.');
}
if (pkg.build?.nsis?.perMachine !== true) {
  errors.push('nsis.perMachine deve ser true para associação .cguard suportada no Windows.');
}
const associations = Array.isArray(pkg.build?.fileAssociations)
  ? pkg.build.fileAssociations
  : (pkg.build?.fileAssociations ? [pkg.build.fileAssociations] : []);
const hasCguard = associations.some((item) => {
  const ext = item?.ext;
  return Array.isArray(ext) ? ext.includes('cguard') : ext === 'cguard';
});
if (!hasCguard) errors.push('build.fileAssociations não registra .cguard.');
const githubPublisher = (pkg.build?.publish ?? []).find((item) => item?.provider === 'github');
if (githubPublisher?.owner !== 'solucionx' || githubPublisher?.repo !== 'CryptoGuard') {
  errors.push('Provider de update deve ser solucionx/CryptoGuard.');
}
for (const file of [
  'build/icon.ico', 'build/installerHeader.bmp', 'build/installerSidebar.bmp',
  'build/uninstallerSidebar.bmp', 'scripts/build-engine.ps1', 'scripts/build-installer.ps1',
  '.github/workflows/release-windows.yml'
]) {
  if (!fs.existsSync(path.join(root, file))) errors.push(`Arquivo obrigatório ausente: ${file}`);
}
const main = fs.readFileSync(path.join(root, 'src/main.js'), 'utf8');
for (const snippet of ['requestSingleInstanceLock()', "'second-instance'", "'open-protected-files'", "'.cguard'"]) {
  if (!main.includes(snippet)) errors.push(`Integração do Explorer ausente em main.js: ${snippet}`);
}
const preload = fs.readFileSync(path.join(root, 'src/preload.js'), 'utf8');
if (!preload.includes('onOpenProtectedFiles')) errors.push('Bridge onOpenProtectedFiles ausente no preload.');

if (errors.length) {
  console.error('Falha na validação da Release:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log(`Release config OK — Crypto Guard ${pkg.version}, NSIS + .cguard + GitHub updater.`);
