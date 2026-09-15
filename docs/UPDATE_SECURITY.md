# Segurança das Atualizações

Desde a **v1.5.1**, o Crypto Guard usa o fluxo NSIS suportado pelo `electron-updater` e GitHub Releases como origem oficial de distribuição.

## Origem fixada

O build contém explicitamente:

```text
provider: github
owner: solucionx
repo: CryptoGuard
```

O renderer não escolhe a origem e o aplicativo não contém PAT/GitHub token. Para usuários finais, o repositório de Releases precisa estar público.

## Fluxo

```text
Abrir Crypto Guard
        ↓
Verificar Release estável
        ↓
Comparar versão instalada
        ↓
Baixar installer + metadata
        ↓
Validar metadata / SHA-512
        ↓
Aguardar operações criptográficas terminarem
        ↓
Instalar NSIS e reiniciar
```

## Controles ativos

- `allowPrerelease = false`;
- `allowDowngrade = false`;
- `disableWebInstaller = true`;
- target Windows limitado a NSIS completo;
- metadata `latest.yml` gerado no mesmo pipeline da Release;
- `.blockmap` publicado junto da versão;
- SHA-256 adicional publicado para verificação humana/forense;
- erro de rede ou GitHub nunca bloqueia a aplicação;
- uma atualização pronta não interrompe criptografia/descriptografia ativa;
- tags/Releases não devem ser sobrescritas: correções recebem nova versão;
- GitHub Actions publica o instalador a partir do código versionado e gera attestation quando o repositório é público.

## Limite atual: assinatura Authenticode

Enquanto a Solucionx não possuir um certificado de code signing confiável, o Windows poderá exibir publisher desconhecido. A verificação de metadata/hash protege integridade do download, mas **não substitui identidade criptográfica do publisher** em caso de comprometimento da conta/pipeline do GitHub.

Quando o certificado estiver disponível, o instalador e atualizações deverão ser assinados no workflow antes do hash/attestation final. O certificado/chave privada nunca deve ser versionado.

## Segredos

Nunca colocar no aplicativo ou repositório:

- `GH_TOKEN`/PAT de usuário;
- chave privada de code signing;
- senha de certificado;
- `.pfx`/`.p12`;
- tokens de API.
