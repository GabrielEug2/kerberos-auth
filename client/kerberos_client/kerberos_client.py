
from kerberos_client.auth_service_client import AuthServiceClient
from kerberos_client.exceptions import ServiceDownError, ServerError, InvalidResponseError

class KerberosClient:
    """Cliente de um sistema de autenticação Kerberos."""
    
    def __init__(self, client_id, client_key):
        """Cria uma instância do cliente.
        
        Args:
            client_id (str): ID do cliente.
            client_key (bytes): Chave do cilente.
        """

        self.client_id = client_id
        self.key = client_key

    def acquire_new_ticket(self, service_id, requested_expiration_time):
        """Obtem um ticket para uso de um determinado serviço.
        
        Contacta o Serviço de Autenticação (AS) e o Serviço de
        Concessão de Tickets (TGS) para obter um ticket que
        garante acesso ao serviço escolhido. Este ticket será
        salvo localmente em um arquivo.
       
        Args:
            service_id (str): ID do serviço desejado
            requested_expiration_time (str): Até quando quer acessar, no formato "DD/MM/YY-hh:mm"
        """

        print("Autenticando no Serviço de Autenticação (AS)... ")
        try:
            session_key_TGS, ticket_for_TGS = AuthServiceClient.request_access_to_service(
                self.client_id,
                self.key,
                service_id,
                requested_expiration_time
            )
        except ServiceDownError:
            print("[Erro] Serviço de autenticação está offline")
            return False
        except ServerError as e:
            print("[Erro] Serviço de autenticação retornou um erro")
            print(e)
            return False
        except InvalidResponseError as e:
            print("[Erro] Não foi possível parsear a resposta do serviço de autenticação")
            print(e)
            return False

        print("Obtendo ticket de acesso através do TGS...")
        #session_key_TGS, ticket_for_TGS

        return True

    def use_service(self, service_id):
        pass