import path from 'node:path';
import fs from 'node:fs';
import { flipFuses, FuseVersion, FuseV1Options } from '@electron/fuses';

export default async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;

  const candidates = [
    path.join(context.appOutDir, 'CryptoGuard.exe'),
    path.join(context.appOutDir, 'Crypto Guard.exe'),
  ];
  const executable = candidates.find((candidate) => fs.existsSync(candidate));
  if (!executable) {
    throw new Error(`Executável Electron não encontrado em ${context.appOutDir} para aplicar fuses.`);
  }

  await flipFuses(executable, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  });
}
