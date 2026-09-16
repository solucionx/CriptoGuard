# Crypto Guard — Especificação criptográfica CGUARD v4

## Escopo

A v1.6.1 cria e lê somente o formato CGUARD v4. O formato foi desenhado para criptografia local por senha de arquivos e pastas. Transferência E2E entre usuários não faz parte desta versão.

## Primitivas

- KDF: Argon2id, `salt` de 16 bytes.
- Perfil de escrita: `memory_kib=65536`, `iterations=3`, `parallelism=1`, saída de 32 bytes.
- Key schedule: HKDF-SHA-256 com `container_id` de 16 bytes como salt do HKDF e `info="CryptoGuard/v4/key-schedule"`.
- Saída do HKDF: 64 bytes, divididos em `content_key` e `metadata_key`, 32 bytes cada.
- AEAD: AES-256-GCM, tag de 16 bytes.
- Chunk padrão: 4 MiB.

## Framing físico

```text
MAGIC                10 bytes: CGUARD0040
HEADER_LEN            4 bytes, unsigned big-endian
HEADER                HEADER_LEN bytes, JSON UTF-8 estrito
METADATA_CIPHERTEXT   tamanho declarado no header
CHUNK_0               plaintext_len(0) + 16 bytes
CHUNK_1               plaintext_len(1) + 16 bytes
...
```

Não há trailer opcional. O tamanho físico esperado do arquivo é calculado a partir do header e deve corresponder exatamente ao tamanho real. Bytes extras e truncamento são rejeitados antes do KDF.

## Schema do header

Somente estes campos são aceitos:

```json
{
  "version": 4,
  "cipher": "AES-256-GCM-CHUNKED",
  "kdf": "argon2id",
  "kdf_params": {
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "length": 32
  },
  "hkdf": "HKDF-SHA256",
  "salt": "base64(16 bytes)",
  "container_id": "base64(16 bytes)",
  "metadata_nonce": "base64(12 bytes)",
  "nonce_prefix": "base64(4 bytes)",
  "chunk_size": 4194304,
  "chunk_count": 1,
  "plaintext_size": 0,
  "metadata_ciphertext_size": 123
}
```

Regras do parser:

- campos extras ou ausentes são rejeitados;
- chaves JSON duplicadas são rejeitadas;
- `NaN` e `Infinity` são rejeitados;
- tipos devem ser exatos; `true`/`false` não são aceitos como inteiros;
- Base64 é validado estritamente e deve produzir o tamanho exato;
- `chunk_count` precisa ser matematicamente consistente com `plaintext_size` e `chunk_size`;
- os parâmetros Argon2id devem estar dentro dos limites defensivos definidos em `constants.py` antes do KDF ser executado.

## Binding do header

```text
header_binding = SHA-256(MAGIC || HEADER_LEN || HEADER)
```

Esse binding entra no AAD de metadados e de todos os chunks. Portanto alterar qualquer byte do header faz a autenticação falhar, desde que o atacante não possua a senha e recrie legitimamente o contêiner.

## Metadados protegidos

O nome original não aparece no header público. Os metadados são JSON canônico e cifrados com `metadata_key`:

```json
{
  "kind": "file | directory",
  "original_name": "nome.ext",
  "payload_format": "raw | zip-deflate",
  "directory_size": null,
  "entry_count": null
}
```

Para pastas, `directory_size` e `entry_count` são inteiros autenticados; para arquivo são `null`.

AAD de metadados:

```text
"CGUARD/v4/metadata\0" || container_id || header_binding
```

## Nonce de conteúdo

Cada contêiner gera um `nonce_prefix` aleatório de 4 bytes. O nonce de cada chunk é:

```text
nonce_i = nonce_prefix || uint64_be(i)
```

O índice começa em zero. A construção garante nonces diferentes para todos os chunks sob a mesma `content_key` sem depender de uma nova amostra aleatória por chunk.

## AAD dos chunks

```text
"CGUARD/v4/chunk\0"
|| container_id
|| header_binding
|| uint64_be(chunk_index)
|| uint64_be(chunk_count)
|| uint64_be(plaintext_size)
```

Isso liga cada ciphertext à posição correta, ao número total de chunks e ao tamanho total autenticado do payload.

## Arquivo vazio

Um payload de zero bytes usa `chunk_count=1` e cifra um plaintext vazio. O resultado é uma tag GCM de 16 bytes. Isso evita um contêiner sem autenticação de conteúdo.

## Operação transacional

Na criptografia, o arquivo é escrito em temporário. Depois o temporário é reaberto, metadados e todos os chunks são autenticados, cada bloco restaurado é comparado diretamente aos bytes da origem e o SHA-256/tamanho também são conferidos. Só então o temporário recebe o nome `.cguard` definitivo e, se solicitado, o original é removido.

### Modo extremo de remoção

Quando explicitamente ativado, o modo extremo só começa **depois** que o `.cguard` definitivo passou por todo o round-trip. O Crypto Guard então sobrescreve best-effort os bytes visíveis do arquivo original (ou de cada arquivo da árvore de uma pasta), sincroniza as gravações e remove as entradas. Para pastas, o ZIP temporário plaintext também recebe essa tentativa de sobrescrita antes da remoção. O recurso aceita 1, 2, 3 ou 7 passadas.

Essa operação **não é uma garantia de apagamento físico** em SSD/NVMe, TRIM, wear-leveling, copy-on-write, journaling, snapshots, backups ou serviços de sincronização. Por isso a interface usa o termo “sobrescrita best-effort”, não “secure erase”. O cancelamento fica indisponível durante operações iniciadas em modo extremo para evitar interrupção destrutiva no meio da sobrescrita.


Na descriptografia, o payload vai para um temporário. O nome final só é criado depois de todos os chunks autenticarem e o framing físico ser consumido exatamente.

## Pastas

Pastas são compactadas em ZIP antes da criptografia. Antes de cifrar, o ZIP temporário é reaberto e o conjunto de caminhos, tamanhos e bytes de cada arquivo é comparado à pasta de origem. O ZIP fica integralmente dentro do payload autenticado. Na restauração, o aplicativo rejeita links simbólicos, path traversal e caminhos absolutos, e compara contagem/tamanho lógico contra os metadados protegidos.

## Limpeza de memória

`master_key`, material expandido e chaves mutáveis são sobrescritos best-effort quando saem de uso. Python, bibliotecas nativas, pagefile, crash dumps e cópias internas impedem garantia de zeroização completa. A documentação e a UI não tratam essa mitigação como garantia absoluta.

## Vetores e CI

`tests/vectors/` contém contêineres v4 determinísticos e um manifesto com SHA-256. A suíte também inclui KATs AES-GCM, HKDF-SHA-256 e Argon2id+HKDF, testes de adulteração, chunking, schema e fuzz-smoke.
