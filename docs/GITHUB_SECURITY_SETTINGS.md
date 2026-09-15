# Configuração recomendada do GitHub

Estas opções são configurações do repositório/organização e não podem ser garantidas apenas pelos arquivos versionados.

## Settings → Security / Code security

Ative Secret scanning, Push protection, Dependabot alerts, Dependabot security updates e Private vulnerability reporting. Em repositórios públicos, o GitHub disponibiliza gratuitamente várias dessas proteções.

## Settings → Actions → General

- Default workflow permissions: **Read repository contents permission**.
- Desabilite aprovação automática de PRs pelo `GITHUB_TOKEN`.
- Prefira permitir apenas Actions da GitHub e Actions explicitamente aprovadas.
- Quando a política estiver disponível, exija pin de Actions por SHA completo.

## Ruleset da `main`

Exija Pull Request, status checks (`CI`, `CodeQL`, `Dependency Review`, `Public repository audit`), bloqueie force-push e deleção e exija resolução de conversas. Se você for o único mantenedor, aprovação humana obrigatória pode ser ativada somente quando houver outro revisor confiável, para evitar lock-out operacional.

## Ruleset de tags

Proteja `v*` contra exclusão e alteração. Uma versão publicada nunca deve ter seu conteúdo silenciosamente substituído; publique uma nova tag de patch.

## Environment de release

Crie um environment chamado `production-release`. Quando houver outra pessoa confiável na equipe, configure reviewer obrigatório. Chaves/certificados futuros de assinatura devem ficar vinculados a esse environment ou, preferencialmente, em serviço de assinatura/KMS com OIDC.
