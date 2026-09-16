# Changelog

## 1.6.1 — Desktop integration / UI restoration

- Restaura a associação do Windows para `.cguard` com nome e ícone do Crypto Guard no Explorer.
- Duplo clique em um `.cguard` abre/reutiliza o Crypto Guard, seleciona o arquivo e navega diretamente para **Descriptografar**.
- Suporte a segunda instância: abrir outro `.cguard` reutiliza a janela existente em vez de iniciar cópia concorrente.
- Mantém a exceção necessária para o relançamento UAC usado nas operações que exigem elevação.
- Corrige o alinhamento do status no rodapé da barra lateral.
- Corrige o espaçamento/alinhamento de “Desenvolvido pela Solucionx” na tela Sobre.
- Preserva CGUARD v4, Argon2id, HKDF-SHA-256, AES-256-GCM em chunks, Modo Extremo e auto-update.
- Mantém a correção UTF-8 do workflow de Release para geração do inventário `pip inspect`.

## 1.6.0 — CGUARD v4 / Cryptographic Hardening

- Novo formato `CGUARD v4`; a v1.6 cria e lê somente v4.
- KDF migrado de Scrypt para Argon2id (`64 MiB`, 3 iterações, paralelismo 1 por padrão).
- HKDF-SHA-256 adicionado para separação entre chave de conteúdo e chave de metadados.
- AES-256-GCM passa a operar em chunks autenticados de 4 MiB, cada um com nonce determinístico e exclusivo por índice.
- Cabeçalho público ligado ao AAD por SHA-256 e parser com schema estrito.
- Chaves JSON duplicadas, campos extras, tipos errados e valores fora de limites são rejeitados.
- Nome original e metadados de pasta deixam de aparecer em claro e passam para bloco de metadados cifrado.
- Tamanho físico do contêiner validado antes de Argon2id; truncamento e bytes extras são rejeitados.
- Criptografia transacional com round-trip completo, comparação byte a byte da origem e SHA-256 antes de remover o original.
- Para pastas, o ZIP temporário é reaberto e comparado à árvore de origem antes da criptografia.
- Descriptografia transacional; resultados parciais nunca recebem o nome final.
- Modo extremo preservado em desenho mais seguro: nunca criptografa em-loco; primeiro cria e valida o CGUARD v4 e só então sobrescreve best-effort o original antes de removê-lo. Passadas disponíveis: 1, 2, 3 ou 7; sem garantia de eliminação física em SSD/NVMe.
- Limpeza best-effort de buffers mutáveis de chave.
- Compatibilidade `.sxcrypt`/v1-v3 removida do fluxo principal.
- Suite ampliada com KATs, tamper tests, chunk-order tests, fuzz-smoke e vetores v4 permanentes.
- UI e documentação atualizadas para CGUARD v4 / Argon2id.

## 1.5.0 — Auto Update

- Migração da distribuição Windows para instalador NSIS.
- Verificação automática de atualização ao iniciar.
- Download em segundo plano e instalação somente fora de operações criptográficas ativas.
- `electron-updater` sem token embutido, sem downgrade e sem pre-release no canal estável.

## 1.4.x

- Build Windows de executável único, hardening Electron e melhorias de publicação.
