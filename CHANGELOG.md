# Changelog

## 1.6.5 — Extreme-mode self-protection

- Corrige uma regressão crítica observada apenas no **Modo Extremo**, na qual o bundle do motor podia desaparecer após uma operação destrutiva.
- O Modo Extremo agora faz **preflight completo antes de qualquer sobrescrita**.
- Bloqueia seleção da pasta de instalação do Crypto Guard, seus pais e seus descendentes protegidos.
- Rejeita symlinks, Windows junctions/reparse points e hard links antes de sobrescrever qualquer byte.
- Garante que todos os arquivos sobrescritos permaneçam dentro da árvore explicitamente selecionada.
- O engine PyInstaller protege a própria instalação mesmo se o chamador omitir a lista de caminhos protegidos.
- O Electron passa explicitamente a raiz instalada, `resources` e o executável do motor como caminhos protegidos.
- O smoke test do Windows agora executa uma criptografia real de **pasta em Modo Extremo** e compara o manifesto SHA-256 completo do bundle do motor antes/depois. A Release falha se o modo extremo tocar no motor.
- Mantém CGUARD v4, Argon2id, HKDF-SHA-256, AES-256-GCM em chunks, updater, associação `.cguard` e identidade visual atual.

## 1.6.4 — Large-folder / engine reliability

- Corrige a comunicação do motor criptográfico para JSON ASCII-only, evitando corrupção de acentos por páginas de código legadas do Windows.
- Troca o motor PyInstaller de `onefile` para `onedir`, reduzindo autoextração temporária e melhorando a estabilidade do backend empacotado.
- O build agora falha se o bundle do motor não estiver realmente presente dentro de `win-unpacked/resources` antes de gerar a Release.
- Adiciona journal transacional local: se o motor for interrompido depois de o `.cguard` ter sido criado e verificado, a interface informa explicitamente que o contêiner foi confirmado e que a remoção do original não foi concluída.
- Erros de encerramento do motor agora incluem diagnóstico real (stderr/código de saída), em vez do genérico “Resposta inválida do motor criptográfico”.
- Adiciona verificação preventiva de espaço livre. Pastas exigem margem para o ZIP temporário e o CGUARD coexistirem durante a operação.
- Mensagem de motor ausente agora diferencia instalação incompleta de possível remoção/quarentena por software de segurança.
- Preserva CGUARD v4, Argon2id, AES-256-GCM em chunks, HKDF, Modo Extremo, associação `.cguard`, auto-update e interface oficial fixa.

## 1.6.3 — Auto-update restart reliability

- Corrige o fluxo em que a atualização era instalada em modo NSIS silencioso e o Crypto Guard podia fechar sem reabrir.
- Atualizações continuam sendo verificadas e baixadas automaticamente, mas não fecham mais o aplicativo assim que o download termina.
- Quando a atualização estiver pronta, o botão passa para **Instalar e reiniciar**.
- A instalação usa o fluxo NSIS visível (`isSilent=false`) com reabertura forçada do aplicativo ao concluir.
- `autoInstallOnAppQuit` fica desativado para evitar instalações implícitas fora do fluxo controlado do app.
- Durante `quitAndInstall`, o handler `window-all-closed` não antecipa `app.quit()`, deixando o updater concluir a sequência de encerramento e instalação.
- Nenhuma alteração em CGUARD v4, Argon2id, Modo Extremo, associação `.cguard` ou interface oficial fixa.

## 1.6.2 — Fixed official interface

- Remove a tela e o item de navegação **Aparência**, que haviam sido reintroduzidos indevidamente.
- Remove personalização de tema, cor de destaque, arredondamento e densidade; a interface volta a usar a identidade visual oficial fixa do Crypto Guard.
- Ignora preferências antigas de aparência salvas no `localStorage`, evitando que instalações atualizadas alterem a identidade oficial.
- Mantém associação `.cguard`, duplo clique direto para **Descriptografar**, Modo Extremo, CGUARD v4, Argon2id, auto-update e correção UTF-8 do workflow.
- Nenhuma alteração no formato criptográfico CGUARD v4 ou na compatibilidade de contêineres v4.

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
