# Threat Model — Crypto Guard 1.6 / CGUARD v4

## Objetivo

Proteger a confidencialidade e a integridade de arquivos e pastas armazenados como `.cguard` quando o atacante obtém o contêiner mas não conhece a senha.

## Ameaças tratadas

- leitura offline do conteúdo do contêiner;
- alteração do header, metadados, ciphertext ou tags;
- reordenação, duplicação, truncamento ou remoção de chunks;
- bytes extras anexados ao contêiner;
- tentativa de enfraquecer parâmetros do KDF modificando o header;
- headers JSON malformados, duplicados ou com tipos inesperados;
- parâmetros que tentem provocar consumo excessivo de memória/CPU além dos limites configurados;
- path traversal e links simbólicos durante restauração de pastas;
- interrupção cooperativa durante criptografia/descriptografia.

## Fora do escopo

- endpoint já comprometido por malware, RAT, keylogger ou administrador hostil;
- captura do plaintext antes da criptografia ou depois da restauração;
- extração de segredo de RAM por adversário com privilégios suficientes;
- pagefile, hibernação, crash dumps e cópias do sistema operacional;
- cópias do plaintext em backups, sincronizadores, snapshots ou histórico do filesystem;
- garantia de secure erase em SSD/NVMe;
- recuperação de senha esquecida;
- transferência E2E entre usuários.

## Senhas

Argon2id aumenta o custo de tentativa offline, mas não transforma senha fraca em segredo forte. Novas criptografias exigem pelo menos 12 caracteres; frases-senha longas continuam preferíveis.

## Nonces

Dentro de cada contêiner, o nonce de conteúdo combina um prefixo aleatório com índice monotônico de 64 bits. O key schedule deriva chave nova por contêiner a partir de salt aleatório e `container_id`. O código não oferece API para o usuário escolher nonce.

## Temporários de pastas

A compactação de diretórios usa um ZIP plaintext temporário local. Ele é removido ao finalizar, mas a remoção não equivale a eliminação física garantida. Para threat models que incluem análise forense do disco, use criptografia integral de disco e políticas adequadas de armazenamento.

## Atualizador

Comprometimento do canal de atualização pode comprometer o endpoint e, portanto, todo o modelo de segurança. O updater não contém token GitHub, recusa downgrade/pre-release e valida metadata do `electron-updater`. Assinatura Authenticode é recomendada como camada adicional de identidade do publisher.


## Remoção do original / modo extremo

O modo extremo reduz a recuperabilidade lógica em alguns cenários ao sobrescrever best-effort arquivos antes da exclusão. Ele não protege contra cópias anteriores, snapshots, backups, sincronização em nuvem, journaling, remapeamento interno de SSD/NVMe, TRIM ou wear-leveling. Criptografia integral de disco e procedimentos de sanitize do dispositivo continuam fora do escopo do Crypto Guard.
