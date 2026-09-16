<p align="center">
  <img src="docs/assets/readme-header.png" alt="Crypto Guard — Encrypt / Decrypt Software" width="100%">
</p>

<p align="center">
  <a href="https://github.com/solucionx/CryptoGuard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/solucionx/CryptoGuard/ci.yml?branch=main&style=for-the-badge&label=CI&labelColor=012659&color=006496" alt="CI"></a>
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-012659?style=for-the-badge&logo=windows11&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/CGUARD-v4-004676?style=for-the-badge" alt="CGUARD v4">
  <img src="https://img.shields.io/badge/Argon2id-KDF-006496?style=for-the-badge" alt="Argon2id">
  <img src="https://img.shields.io/badge/AES--256--GCM-Chunked-004676?style=for-the-badge" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/Vers%C3%A3o-1.6.3-003061?style=for-the-badge" alt="Versão 1.6.3">
</p>

<p align="center"><strong>Criptografia local de arquivos e pastas para Windows.</strong><br>Seus arquivos. Sua privacidade. Seu controle.</p>
<p align="center">Desenvolvido pela <strong>Solucionx</strong></p>

---

## Visão geral

**Crypto Guard 1.6.3** usa a **identidade visual oficial fixa** e consolida o formato **CGUARD v4** e restaura a integração do Windows com arquivos `.cguard`. O aplicativo criptografa e descriptografa arquivos e pastas localmente; arquivos e senhas não são enviados para servidores durante o fluxo criptográfico.

A v4 foi desenhada para reduzir erros comuns de formatos criptográficos próprios: nonce reutilizado, parâmetros KDF permissivos, parser ambíguo, metadados em claro, arquivos parciais tratados como válidos e operações GCM gigantes.

### Principais propriedades

- **Argon2id** para derivação da chave mestra (`64 MiB`, `3` iterações, paralelismo `1` por padrão).
- **HKDF-SHA-256** para separar a chave de conteúdo da chave de metadados.
- **AES-256-GCM** em chunks autenticados de `4 MiB`.
- Nonce de conteúdo formado por prefixo aleatório de 32 bits + índice de chunk de 64 bits.
- Salt aleatório de 128 bits, `container_id` aleatório e nonce de metadados aleatório por contêiner.
- Cabeçalho público incluído indiretamente no AAD por um binding SHA-256.
- Nome original, tipo de conteúdo e metadados de pasta ficam **dentro da área criptografada**.
- Parser v4 com schema estrito: campos extras, ausentes, duplicados, tipos incorretos e limites inválidos são rejeitados.
- Tamanho físico esperado do contêiner é validado antes do KDF, reduzindo superfícies de truncamento e abuso de recursos.
- Criação transacional: o `.cguard` final só aparece após uma segunda passagem que autentica todo o arquivo e compara o payload restaurado ao payload de origem.
- Descriptografia transacional: plaintext é produzido em arquivo temporário e só recebe o nome final após todos os chunks serem autenticados.
- Cancelamento cooperativo remove resultados temporários e preserva a origem quando a operação ainda não foi concluída.
- Zeroing best-effort de buffers de chave mutáveis; não é tratado como garantia de eliminação absoluta da memória.
- CI com KATs, testes de adulteração, parser estrito, fuzz-smoke e vetores permanentes de formato.

- **Modo extremo opcional** preservado: depois do round-trip completo do `.cguard`, o original pode ser sobrescrito best-effort (1/2/3/7 passadas) e então removido. Não é apresentado como “secure erase” garantido, especialmente em SSD/NVMe, TRIM, snapshots, backups ou armazenamento sincronizado.

> A v1.6 cria e lê somente **CGUARD v4**. Formatos v1/v2/v3 e `.sxcrypt` foram removidos do fluxo principal para manter a implementação v4 menor e mais auditável.

---

## Segurança criptográfica

O fluxo de chaves é:

```text
senha
  │
  ├─ Argon2id(password, salt)
  │        ↓
  │    master key (32 bytes)
  │        ↓
  └─ HKDF-SHA-256 + container_id
           ├─ content_key  (32 bytes)
           └─ metadata_key (32 bytes)
```

O payload é dividido em chunks independentes:

```text
chunk 0 ─ AES-256-GCM ─ ciphertext + tag
chunk 1 ─ AES-256-GCM ─ ciphertext + tag
chunk 2 ─ AES-256-GCM ─ ciphertext + tag
...
```

Cada chunk recebe AAD que liga o bloco ao contêiner e à posição correta. Reordenar, duplicar, remover, truncar ou alterar um chunk faz a autenticação falhar.

### Nonces

Para conteúdo:

```text
nonce = random_prefix[4 bytes] || chunk_index[8 bytes big-endian]
```

Assim, dentro de um contêiner, não existe escolha aleatória de nonce por bloco que possa colidir: a unicidade é determinística por índice. A chave de conteúdo também é derivada especificamente para aquele contêiner.

Metadados usam chave separada e nonce aleatório de 96 bits.

### Cabeçalho v4

O cabeçalho público contém apenas o necessário para derivar a chave e interpretar o framing do contêiner. Ele não contém o nome original do arquivo.

Campos aceitos na v4:

```text
version
cipher
kdf
kdf_params
hkdf
salt
container_id
metadata_nonce
nonce_prefix
chunk_size
chunk_count
plaintext_size
metadata_ciphertext_size
```

Qualquer campo desconhecido ou ausente é rejeitado. `bool` não é aceito como inteiro, chaves JSON duplicadas são recusadas e parâmetros Argon2id/chunking têm limites absolutos antes da alocação de recursos.

Detalhes completos: [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md).

---

## Integridade e round-trip

Antes de remover a origem, a v1.6 executa uma segunda leitura independente do `.cguard` temporário:

```text
payload de origem ───────────────┐
                                      │ comparação byte a byte
.cguard temporário                    │
       ↓ autenticar metadados         │
       ↓ autenticar/decriptar chunks ─┘
       ↓ confirmar SHA-256 e tamanho
       ↓
renomeia temporário para arquivo.cguard
       ↓
somente então tenta remover a origem
```

Essa etapa não substitui a autenticação GCM; cada bloco restaurado é comparado diretamente aos bytes da origem e o SHA-256/tamanho também são confirmados. Para pastas, o ZIP temporário é primeiro reaberto e comparado byte a byte à árvore de origem antes de ser criptografado.

---

## Pastas

Pastas são transformadas em um ZIP temporário, e esse ZIP é reaberto para validar a estrutura e comparar byte a byte cada arquivo com a pasta de origem; somente então o ZIP inteiro é protegido pelo CGUARD v4. Na restauração, o ZIP só é extraído depois que todo o payload criptográfico foi autenticado.

A extração bloqueia path traversal, caminhos absolutos e links simbólicos. O total de itens e o tamanho lógico da pasta são armazenados em metadados criptografados e verificados na restauração.

> Durante a preparação de uma pasta existe um ZIP plaintext temporário local. Ele é removido ao final, mas a exclusão de um arquivo temporário não equivale a apagamento físico garantido em SSDs, snapshots, journaling ou armazenamento sincronizado. Criptografia integral de disco continua recomendada para máquinas que manipulam material sensível.

---

## Limites e premissas

Crypto Guard protege dados **em repouso dentro do contêiner**. Ele não protege um computador já comprometido por malware, keylogger, captura de tela, acesso administrativo à memória ou cópias externas do plaintext.

A limpeza de buffers em Python é best-effort. Bibliotecas nativas, o interpretador, paginação de memória e crash dumps podem manter cópias fora do controle direto do aplicativo.

Nenhum software deve prometer “apagamento seguro” de arquivo individual em todos os tipos de armazenamento. O Crypto Guard não apresenta exclusão normal como secure erase.

Veja [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Arquitetura

```text
┌──────────────────────────────┐
│      Renderer HTML/CSS/JS    │
│   sem acesso direto ao Node  │
└──────────────┬───────────────┘
               │ IPC mínimo via preload
               ▼
┌──────────────────────────────┐
│        Electron Main         │
│ diálogos, ciclo de vida, IPC │
└──────────────┬───────────────┘
               │ stdin/stdout JSON
               ▼
┌──────────────────────────────┐
│      Python Crypto Engine    │
│  CGUARD v4 / Argon2id / GCM │
└──────────────┬───────────────┘
               │
               ▼
          arquivo .cguard
```

O renderer usa `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false` e CSP local. Senhas são enviadas ao motor pelo `stdin` do processo filho, não por argumentos de linha de comando.

---

## Estrutura do motor v4

```text
python/
├── bridge.py
├── crypto_guard.py
└── cryptoguard/
    ├── archive.py
    ├── constants.py
    ├── container_v4.py
    ├── engine.py
    ├── errors.py
    ├── format_v4.py
    ├── io_utils.py
    ├── kdf.py
    ├── memory.py
    └── strict_json.py

tests/
├── test_crypto_guard.py
├── test_kat.py
├── test_parser_fuzz.py
├── test_v4_security.py
├── test_vectors.py
└── vectors/
```

---

## Desenvolvimento

Ambiente recomendado:

- Windows 10/11 x64
- Node.js `24.20.x`
- Python `3.12.x`

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\python\requirements.txt
npm ci
npm start
```

Dependências criptográficas Python são fixadas em `python/requirements.txt`.

---

## Testes

```powershell
python -m unittest discover -s tests -v
node --check .\src\main.js
node --check .\src\preload.js
node --check .\src\renderer.js
python .\scripts\public-release-audit.py
```

A suíte cobre, entre outros casos:

- KAT AES-256-GCM;
- KAT HKDF-SHA-256 RFC 5869;
- KAT do key schedule Argon2id + HKDF do Crypto Guard;
- round-trip de arquivo, pasta e arquivo vazio;
- senha incorreta;
- não reutilização de salt/prefixo/ID entre operações;
- alteração de metadados/ciphertext/tag;
- chunks reordenados e duplicados;
- truncamento e bytes extras;
- schema estrito e chaves JSON duplicadas;
- fuzz-smoke de headers malformados;
- cancelamento transacional;
- falha forçada de verificação sem remoção da origem;
- vetores `.cguard` permanentes para compatibilidade futura.

---

## Build Windows

```powershell
npm run build:win
```

Saída esperada:

```text
release/
├── CryptoGuard-Setup.exe
├── CryptoGuard-Setup.exe.blockmap
├── CryptoGuard-Setup.exe.sha256
└── latest.yml
```

O usuário final não precisa instalar Python ou Node; o motor Python é empacotado pelo PyInstaller e incluído como recurso do aplicativo Electron.

---

## Atualizações

A build instalada usa NSIS + `electron-updater`. A verificação de atualização não faz parte do fluxo criptográfico e uma atualização pronta aguarda operações criptográficas ativas terminarem antes de reiniciar o aplicativo.

Nenhum token GitHub é embutido no aplicativo. Pre-releases e downgrade são recusados. Authenticode continua recomendado para fortalecer a identidade do publisher quando um certificado da Solucionx estiver disponível.

Detalhes: [`docs/UPDATE_SECURITY.md`](docs/UPDATE_SECURITY.md).

---

## Publicação e segurança

- [`SECURITY.md`](SECURITY.md) — reporte responsável de vulnerabilidades.
- [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) — especificação CGUARD v4.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — limites e ameaças.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — fronteiras de processo.
- [`PUBLICATION_READINESS.md`](PUBLICATION_READINESS.md) — checklist pré-publicação.

O código é disponibilizado para transparência e auditoria sob os termos descritos em [`SOURCE_AVAILABLE_NOTICE.md`](SOURCE_AVAILABLE_NOTICE.md). O projeto permanece marcado como `UNLICENSED`; isso não equivale a uma licença open source.

**Produto:** Crypto Guard  
**Versão:** `1.6.3`  
**Formato:** `CGUARD v4`  
**Extensão:** `.cguard`  
**App ID:** `com.solucionx.cryptoguard`  
**Desenvolvido pela:** **Solucionx**

<p align="center"><img src="docs/assets/crypto-guard-mark.png" alt="Crypto Guard" width="96"><br><sub>Copyright © 2026 Solucionx. Todos os direitos reservados.</sub></p>
