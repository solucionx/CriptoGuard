# Threat Model

## Ativos protegidos

1. Conteúdo em texto claro selecionado pelo usuário.
2. Senha informada pelo usuário.
3. Integridade e autenticidade de contêineres `.cguard`.
4. Integridade do executável distribuído.
5. Integridade da cadeia de atualização.

## Fronteiras de confiança

- Renderer Electron é tratado como menos privilegiado que o processo principal.
- O renderer não recebe Node.js diretamente (`nodeIntegration: false`).
- O IPC é exposto por uma API reduzida no preload.
- O engine recebe solicitações estruturadas por stdin/stdout, não senha por argumentos de processo.
- Downloads futuros de atualização são considerados não confiáveis até validação criptográfica completa.

## Ameaças tratadas

- senha incorreta e adulteração do contêiner;
- path traversal/Zip Slip;
- links simbólicos inesperados em conteúdo compactado;
- parâmetros KDF abusivos;
- arquivos parciais em falhas comuns;
- exposição de senha na linha de comando;
- comprometimento do renderer por redução de privilégios/CSP;
- supply-chain no CI por permissões mínimas e Actions fixadas em commit SHA;
- introdução acidental de segredos por auditoria local e Secret Scanning do GitHub público.

## Fora de escopo

- host já controlado por malware/administrador adversário;
- keylogger ou captura de tela do sistema;
- ataque físico/forense contra SSD com garantias de secure erase;
- recuperação de senha esquecida;
- proteção contra alteração do binário enquanto não houver code signing/Authenticode de produção.
