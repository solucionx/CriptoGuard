# Política de Segurança — Crypto Guard

A segurança do Crypto Guard inclui o motor criptográfico, o aplicativo Electron, o pipeline de build, as Releases e o futuro sistema de atualização.

## Versões suportadas

A versão estável mais recente recebe correções de segurança. Correções críticas podem ser retroportadas quando houver necessidade técnica.

## Relatar uma vulnerabilidade

**Não abra uma Issue pública para vulnerabilidades.** Use o recurso privado do GitHub em **Security → Advisories → Report a vulnerability**.

Inclua, quando possível, versão afetada, impacto, passos mínimos para reproduzir e logs já sanitizados. Não envie senhas reais, chaves privadas, certificados, tokens, arquivos pessoais ou dados de terceiros.

## Escopo de maior sensibilidade

São consideradas áreas de alto risco: criptografia/KDF/nonce/salt, parsing do formato `.cguard`, extração de ZIP, exclusão de dados, UAC, IPC Electron ↔ engine, execução de processos, atualização automática, GitHub Actions, geração de Releases e assinatura de código.

## Segredos e assinatura

Nenhum segredo de produção pode existir no repositório. Isso inclui PATs, tokens, `.env`, certificados PFX/P12, chaves privadas PEM, credenciais de serviços e a futura chave privada usada para assinar manifests de atualização.

O cliente poderá conter **somente material público de verificação**, como uma chave pública de atualização.

## Divulgação coordenada

A Solucionx prioriza correções antes de detalhes exploráveis serem publicados. Depois da correção e disponibilização de uma versão segura, um Security Advisory poderá ser publicado com o impacto e a mitigação apropriados.
