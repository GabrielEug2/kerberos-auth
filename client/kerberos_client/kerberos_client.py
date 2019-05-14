
import pkg_resources
import json

from kerberos_client.auth_service import AS
from kerberos_client.ticket_granting_service import TGS
from kerberos_client.exceptions import ServiceDownError, ServerError, InvalidResponseError


CLIENT_DATA_PATH = pkg_resources.resource_filename('kerberos_client', 'client.data')


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
        salvo localmente para usos futuros.
       
        Args:
            service_id (str): ID do serviço desejado
            requested_expiration_time (str): Até quando quer acessar, 
                no formato "DD/MM/YY-hh:mm"
        """

        print("Autenticando no Serviço de Autenticação (AS)... ")
        try:
            session_key_TGS, ticket_for_TGS = AS.request_access_to_service(
                client_id=self.client_id,
                client_key=self.key,
                service_id=service_id,
                requested_expiration_time=requested_expiration_time
            )
        except ServiceDownError:
            print("[Erro] AS está offline")
            return False
        except ServerError as e:
            print("[Erro] AS retornou um erro")
            print(e)
            return False
        except InvalidResponseError as e:
            print("[Erro] Não foi possível parsear a resposta do AS")
            print(e)
            return False

        print("Obtendo ticket de acesso através do Serviço de Concessão de Tickets (TGS)...")
        try:
            session_key, ticket, autorized_time = TGS.request_ticket_for_service(
                client_id=self.client_id,
                service_id=service_id,
                requested_expiration_time=requested_expiration_time,
                session_key=session_key_TGS,
                ticket=ticket_for_TGS
            )
        except ServiceDownError:
            print("[Erro] TGS está offline")
            return False
        except ServerError as e:
            print("[Erro] TGS retornou um erro")
            print(e)
            return False
        except InvalidResponseError as e:
            print("[Erro] Não foi possível parsear a resposta do TGS")
            print(e)
            return False

        with open(CLIENT_DATA_PATH, 'r') as f:
            client_data = json.load(f)

        client_data['tickets'][service_id] = {
            'session_key': session_key.decode(),
            'ticket': ticket.decode(),
            'autorized_time': autorized_time
        }
           
        with open(CLIENT_DATA_PATH, 'w') as f:
            json.dump(client_data, f, indent=4)

        return True

    def use_service(self, service_id):
        pass