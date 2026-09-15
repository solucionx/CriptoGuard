# Criptografia do Crypto Guard

Este documento descreve o formato atual de forma auditável. Ele não deve ser interpretado como certificação formal do produto.

## Primitivas

- Cifra autenticada: AES-256-GCM.
- Derivação de chave: Scrypt.
- Tamanho da chave: 32 bytes (256 bits).
- Salt: 16 bytes aleatórios.
- Nonce GCM: 12 bytes aleatórios por contêiner.
- Tag GCM: 16 bytes.
- Streaming: blocos de 1 MiB.

## Parâmetros Scrypt padrão

- `N = 2^15`
- `r = 8`
- `p = 1`

O parser também impõe limites máximos de custo para evitar que um contêiner malicioso force consumo arbitrário de memória/CPU.

## Autenticação e metadados

O conteúdo e os metadados criptográficos relevantes são autenticados. Uma senha incorreta ou alteração do contêiner faz a autenticação falhar. A senha não é armazenada no arquivo e não existe chave mestra de recuperação.

## Pastas

Pastas são compactadas antes da criptografia. A restauração valida caminhos, bloqueia traversal (`..`/Zip Slip), links simbólicos e limites de entrada antes da extração.

## Limites do modelo

O Crypto Guard não protege contra um sistema operacional já comprometido, keyloggers, malware com privilégios suficientes, leitura de memória do processo ou acesso à senha antes/depois da operação. “Sobrescrever” arquivos também não equivale a garantia de apagamento físico em SSDs com wear-leveling.
