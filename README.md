# Sistema de Autenticação Kerberos

## Como funciona

O Kerberos é um sistema de autenticação que envolve 4 atores:

* __Cliente__: quem vai se autenticar, obter os tickets e acessar os serviços.
* __Serviço de Autenticação (AS)__: quem autentica os clientes. Conhece a chave de todos os clientes.
* __Serviço de Concessão de Tickets (TGS)__: quem concede os tickets de acesso aos serviços. Conhece a chave de todos os serviços.
* __Serviços__: serviços que serão acessados.

Funciona assim:

1. O cliente se autentica junto ao AS.

    * Ele envia uma mensagem __M1__ falando quem ele é, que serviço quer acessar e quando.
        * __M1__ = [ID\_C + *{ID\_S + T\_R + N1}* Kc]

    * O AS gera uma chave de sessão para o cliente e o TGS se comunicarem, e responde com __M2__, que contém: 1) A chave que o cliente deve usar para falar com o TGS; 2) Um ticket que ele deve enviar para o mesmo (criptografado, somente o TGS consegue abrir).
        * __M2__ = [*{K\_c\_tgs + N1}* Kc + T\_c\_tgs]
            * __T\_c\_tgs__ = *{ID\_C + T\_R + K\_c\_tgs}* K\_tgs

2. O cliente obtém um ticket de acesso ao serviço (servidor) desejado do TGS.

    * Ele envia __M3__, que diz quem ele é e o que quer acessar, junto com o ticket que o AS deu.
        * __M3__ = [*{ID\_C + ID\_S + T\_R + N2}* K\_c\_tgs + T\_c\_tgs]

    * O TGS verifica se as informações do ticket conferem com as que o cliente enviou na mensagem. Se estiver tudo ok, ele gera uma chave de sessão para o cliente e o serviço se comunicarem, e envia como resposta __M4__, que contém: 1) A chave que o cliente deve usar para falar com o serviço; 2) Um ticket que ele deve mandar para o mesmo (criptografado, somente o serviço consegue abrir).
        * __M4__ = [*{K\_c\_s + T\_A + N2}* K\_c\_tgs + T\_c\_s]
            * __T\_c\_s__ = *{ID\_C + T\_A + K\_c\_s}* K\_s

3. Com esse ticket, o cliente pode se autenticar junto ao servidor desejado e solicitar serviços.

    * O cliente envia uma manesgem __M5__ para o serviço, falando quem ele é e o que ele quer acessar/fazer, junto com o ticket que o TGS deu.
        * __M5__ = [*{ID\_C + (T\_A ou T\_R) + S\_R + N3}* K\_c\_s + T\_c\_s]
    
    * O serviço verifica se as informações do ticket conferem com as que o cliente enviou na mensagem. Se estiver tudo ok, ele responde com __M6__, criptografada com a chave de sessão.
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

Instale com o ```pip```. Isso irá baixar todas as dependências necessárias e colocar os executáveis no PATH:

```sh
pip install -e client/ auth_service/ ticket_granting_service/
```

### Serviço

TODO

---

## Executando

Cada componente é uma aplicação separada, e deve ser executado em um terminal diferente.

Cliente:

```sh
kerberos-client --help
```

Serviço de Autenticação (AS):

```sh
kerberos-as --help
```

Serviço de Concessão de Tickets (TGS):
```sh
kerberos-tgs --help
```

Serviço:
```sh
TODO
```

---

## Detalhes da implementação

* Criptografia utilizada: Fernet (AES-128)
* Tempo solicitado e Tempo autorizado:
    * Strings no formato ```"%d/%m/%y-%H:%M"```, representando a data de validade.