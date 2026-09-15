# Modelo de Segurança para Atualizações

O Crypto Guard será distribuído como um único EXE portátil. O sistema de update será próprio e **não confiará apenas no fato de o arquivo estar hospedado no GitHub**.

## Descoberta

A versão disponível poderá ser descoberta em um repositório público oficial da Solucionx através da API HTTPS do GitHub. Essa consulta serve para descoberta; não é, sozinha, autorização para instalar código.

## Autorização do update

Uma atualização só poderá substituir a versão atual depois de verificar:

1. manifesto de update com formato/versão reconhecidos;
2. assinatura Ed25519 válida do manifesto usando chave pública embutida no app;
3. `product`/canal/repositório esperados;
4. versão semanticamente maior que a instalada (sem downgrade/replay por padrão);
5. tamanho e SHA-256 do `CryptoGuard.exe` exatamente iguais ao manifesto;
6. Authenticode/publisher Solucionx quando o certificado de produção estiver habilitado;
7. download concluído em arquivo temporário antes de qualquer troca;
8. substituição atômica/rollback pelo helper de update.

## O manifesto nunca poderá

- fornecer comandos de shell;
- escolher executáveis arbitrários;
- mudar o repositório/origem de download livremente;
- fornecer caminhos locais arbitrários;
- alterar a chave pública de confiança sem mecanismo explícito de rotação.

## Segredos

O aplicativo nunca conterá PAT/GitHub token. A chave privada Ed25519 nunca será versionada nem empacotada. O repositório conterá no máximo a chave pública.

## Estado atual

A infraestrutura documental está pronta, mas atualizações automáticas não devem ser habilitadas até a verificação criptográfica acima estar implementada e testada.
