# Sistema de Autenticação Kerberos

## Como funciona

O Kerberos é um sistema de autenticação que envolve 4 atores:

* __Cliente__: quem vai se autenticar, obter os tickets e acessar os serviços.
* __Serviço de Autenticação (AS)__: quem autentica os clientes. Conhece a chave de criptografia de todos os clientes e do TGS.
* __Serviço de Concessão de Tickets (TGS)__: quem concede os tickets de acesso aos serviços. Conhece a chave de criptografia de todos os serviços.
* __Serviços__: serviços que serão acessados.

Funciona assim:

1. O cliente se autentica junto ao AS.

    * Ele envia uma mensagem __M1__ falando quem ele é e quando quer acessar o TGS.
        * __M1__ = [ID\_C + *{ID\_S + T\_R + N1}* Kc]
            * *ID_S* nesse caso é o identificador do TGS.

    * O AS gera uma chave de sessão para o cliente e o TGS se comunicarem.
    
    * O AS responde com __M2__, que contém: 1) A chave que o cliente deve usar para falar com o TGS; 2) Um "ticket garantidor de tickets" (_Ticket Granting Ticket_), que ele pode enviar para o TGS para obter acesso aos serviços desejados. Somente o TGS consegue abrir este ticket, para o cliente o ticket é só um monte de bytes.
        * __M2__ = [*{K\_c\_tgs + N1}* Kc + T\_c\_tgs]
            * __T\_c\_tgs__ = *{ID\_C + T\_R + K\_c\_tgs}* K\_tgs
                * *T\_R* nesse caso representa o tempo de validade do ticket.

2. O cliente obtém um ticket de acesso ao serviço (servidor) desejado do TGS.

    * Ele envia __M3__, que diz quem ele é, que serviço quer acessar e quando, junto com o ticket que o AS deu.
        * __M3__ = [*{ID\_C + ID\_S + T\_R + N2}* K\_c\_tgs + T\_c\_tgs]

    * O TGS verifica se o cliente que está escrito no ticket é o mesmo que enviou a mensagem, e se o ticket é válido naquele momento. Se estiver tudo ok, ele gera uma chave de sessão para o cliente e o serviço se comunicarem.
    
    * O TGS envia como resposta __M4__, que contém: 1) A chave que o cliente deve usar para falar com o serviço; 2) Quando o cliente está autorizado a usar o serviço; 3) Um ticket que garante acesso ao serviço. Assim como o ticket anterior, esse ticket são somente bytes para o cliente. Somente o serviço vai conseguir ler o conteúdo.
        * __M4__ = [*{K\_c\_s + T\_A + N2}* K\_c\_tgs + T\_c\_s]
            * __T\_c\_s__ = *{ID\_C + T\_A + K\_c\_s}* K\_s

3. Com esse ticket, o cliente pode se autenticar junto ao servidor desejado e solicitar serviços.

    * O cliente envia uma manesgem __M5__ para o serviço, falando quem ele é e o que ele quer acessar/fazer, junto com o ticket que o TGS deu.
        * __M5__ = [*{ID\_C + (T\_A ou T\_R) + S\_R + N3}* K\_c\_s + T\_c\_s]
    
    * O serviço verifica se o cliente que está escrito no ticket é o mesmo que enviou a mensagem, e se o ticket é válido naquele momento. Se não for o mesmo cliente ou o ticket não for válido, ele nega o acesso.

    * Se estiver tudo ok, ele responde com __M6__, criptografada com a chave de sessão.
        * __M6__ = [*{Resposta, N3}* K\_c\_s]

Legenda:

* ID_C = Identificador do cliente.
* ID_S = Identificador do serviço pretendido.
* T_R = Tempo solicitado pelo Cliente para ter acesso ao serviço.
* N1 = Número aleatório 1.
* Kc = Chave do cliente (Somente o cliente e o AS conhecem).
* T_c_tgs = Ticket fornecido para a comunicação cliente TGS.
* K_c_tgs = Chave de sessão entre cliente e TGS (Gerado no AS randomicamente)
* K_tgs = Chave do Servidor TGS (Somente o TGS e o AS conhecem).
* T_A = Tempo autorizado pelo TGS.
* K_s = Chave do Servidor de serviços (Somente o TGS e o servidor de serviços conhecem).
* S_R = Serviço Requisitado.
* K_c_s = Chave de sessão entre cliente e Servidor de serviço (Gerado no TGS randomicamente)
* N2 = Número aleatório 2.
* N3 = Número aleatório 3

---

## Instalação

### Cliente, AS e TGS

Instale com o ```pip```. Isso irá baixar todas as dependências necessárias:

```sh
pip install -e client/ auth_service/ ticket_granting_service/
```

### Serviço

Instale o [NodeJs](https://nodejs.org/en/download/package-manager/).

Baixe as dependências:

```sh
npm install
```

---

## Executando

Cada componente é uma aplicação separada, e deve ser executado em um terminal diferente.

Cliente:

```sh
kerberos-client --help
```

Serviço de Autenticação (AS):

```sh
cd auth_service/
./bin/start-as-server
```

Serviço de Concessão de Tickets (TGS):
```sh
cd ticket_granting_service/
./bin/start-tgs-server
```

Serviço:
```sh
cd service1
node service1.js
```

---

## Detalhes da implementação

* Criptografia utilizada: Fernet (AES-128 com modo CBC e padding PKCS7)

---