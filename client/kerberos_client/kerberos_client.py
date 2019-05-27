
import pkg_resources
import json

from kerberos_client.communication.as_client import AS
from kerberos_client.communication.tgs_client import TGS
from kerberos_client.communication.service1_client import Service
from kerberos_client.communication.exceptions import ServiceDownError, ServerError, InvalidResponseError

class KerberosClient:
    """Cliente de um sistema de autenticação Kerberos."""

    def __init__(self, client_id):
        """Cria uma instância do cliente.
        
        Args:
            client_id (str): ID do cliente.
        """

        self.client_id = client_id
        self.client_key = self._get_client_key(client_id)

    def acquire_new_ticket(self, service_id, requested_time):
        """Obtem um ticket para uso de um determinado serviço.
        
        Contacta o Serviço de Autenticação (AS) e o Serviço de
        Concessão de Tickets (TGS) para obter um ticket que
        garante acesso ao serviço escolhido.
       
        Args:
            service_id (str): ID do serviço desejado
            requested_time (str): Tempo solicitado.
                Prazo de validade no formato "DD/MM/YY-hh:mm"

        Returns:
            autorizated_time (str): tempo concedido para uso do
                serviço, ou None caso o ticket não tenha sido
                concedido
        """

        print("Autenticando no Serviço de Autenticação (AS)... ")
        try:
            session_key_TGS, ticket_for_TGS = AS.request_access_to_service(
                client_id=self.client_id,
                client_key=self.client_key,
                service_id=service_id,
                requested_time=requested_time
            )
        except ServiceDownError:
            print("[Erro] AS está offline")
            return None
        except ServerError as e:
            print("[Erro] AS retornou um erro")
            print(e)
            return None
        except InvalidResponseError as e:
            print("[Erro] Não foi possível parsear a resposta do AS")
            print(e)
            return None

        print("Obtendo ticket de acesso através do Serviço de Concessão de Tickets (TGS)...")
        try:
            session_key, ticket, autorized_time = TGS.request_ticket_for_service(
                client_id=self.client_id,
                service_id=service_id,
                requested_time=requested_time,
                session_key=session_key_TGS,
                ticket=ticket_for_TGS
            )
        except ServiceDownError:
            print("[Erro] TGS está offline")
            return None
        except ServerError as e:
            print("[Erro] TGS retornou um erro")
            print(e)
            return None
        except InvalidResponseError as e:
            print("[Erro] Não foi possível parsear a resposta do TGS")
            print(e)
            return None

        self._save_ticket(
            service_id,
            autorized_time,
            session_key,
            ticket
        )

        return autorized_time

    def use_service(self, service_id, ticket, session_key):
        """Tenta acessar um serviço com o ticket especificado
        
        Args:
            service_id (str): ID do serviço a ser contactado
            ticket (bytes): Ticket de acesso
            session_key (bytes): Chave de sessão para comunicação com o serviço
        """

        try:
            response = Service.request(
                client_id=self.client_id,
                service_id=service_id,
                ticket=ticket,
                session_key=session_key
            )

        pass

    def available_tickets(self, service_id=None):
        """Retorna uma lista de tickets para uso em serviços
        
        Args:
            service_id (str, optional): ID de serviço para filtrar
                os resultados. Se não for fornecido, serão retornados
                todos os tickets salvos
        
        Returns:
            arr: Lista de tickets que podem ser usados para
                acessar serviços
        """
        
        tickets = self._load_all_tickets()

        if service_id:
            available_tickets = [ticket for ticket in tickets
                                 if ticket['serviceId'==service_id]]
        else:
            available_tickets = tickets

        return tickets
   

    @classmethod
    def save_client(cls, client_id, client_key):
        """Salva um cliente localmente
        
        Args:
            client_id (str): ID do cliente
            client_key (str): Chave do cliente
        
        Returns:
            bool: True em caso de sucesso, False se o cliente já existe
        """

        clients = cls._load_all_clients()

        if client_id not in clients:
            clients[client_id] = { 'key': client_key }

            cls._save_all_clients(clients)
            client_saved = True
        else:
            client_saved = False

        return client_saved
    

    def _get_client_key(self, client_id):
        """Obtém a chave de um cliente, dado seu id"""

        clients = self._load_all_clients()

        try:
            key = clients[client_id]['key'].encode()
        except (KeyError, AttributeError):
            key = None

        return key

    def _save_ticket(self, service_id, autorized_time, session_key, ticket):
        """Salve um ticket para uso futuro"""

        tickets = self._load_all_tickets()

        tickets.append({
            'serviceId': service_id,
            'autorizedTime': autorized_time,
            'sessionKey': session_key.decode(),
            'ticket': ticket.decode()
        })

        self._save_all_tickets(tickets)


    @classmethod
    def _load_all_clients(cls):
        """Carrega todos os clientes em um dict"""

        CLIENTS_PATH = pkg_resources.resource_filename('kerberos_client', 'data/clients.json')

        try:
            with open(CLIENTS_PATH, 'r') as f:
                clients = json.load(f)

        except FileNotFoundError:
            with open(CLIENTS_PATH, 'w') as f:
                json.dump({}, f)
            clients = {}

        return clients

    @classmethod
    def _save_all_clients(cls, clients):
        """Persiste todos os clientes"""

        CLIENTS_PATH = pkg_resources.resource_filename('kerberos_client', 'data/clients.json')

        with open(CLIENTS_PATH, 'w') as f:
            json.dump(clients, f, indent=2)

    @classmethod
    def _load_all_tickets(cls):
        """Carrega todos os tickets em uma lista"""

        TICKETS_PATH = pkg_resources.resource_filename('kerberos_client', 'data/tickets.json')

        try:
            with open(TICKETS_PATH, 'r') as f:
                tickets = json.load(f)
        except FileNotFoundError:
            with open(TICKETS_PATH, 'w') as f:
                json.dump([], f)
            tickets = []

        return tickets
    
    @classmethod
    def _save_all_tickets(cls, tickets):
        """Persiste todos os tickets"""

        TICKETS_PATH = pkg_resources.resource_filename('kerberos_client', 'data/tickets.json')

        with open(TICKETS_PATH, 'w') as f:
            json.dump(tickets, f, indent=2)
