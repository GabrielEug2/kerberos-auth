# Sistema de Autenticação Kerberos

O Kerberos é ...

TODO
- explicação básica
- componentes
- estrutura das mensagens

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
