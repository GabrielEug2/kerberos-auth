
import pkg_resources
import json
from datetime import datetime, timedelta

from kerberos_client.crypto import Crypto
from kerberos_client.communication.as_client import AS
from kerberos_client.communication.tgs_client import TGS
from kerberos_client.communication.service1_client import Service
from kerberos_client.exceptions import (
    ServerDownError, ServerError, InvalidResponseError, UnknownService
)


class KerberosClient:
    """Cliente de um sistema de autenticação Kerberos."""

    def __init__(self):
        self.current_user = None

    def login(self, client_id, password):
        """Faz login localmente."""
        self.current_user = {
            "client_id": client_id,
            "password": password
        }
        
    def sign_up(self, client_id, password):
        """Se registra no AS com o ID especificado
        
        Args:
            client_id (str): ID desejado
            password (str): Senha

        Throws:
            ServerDownError: se o AS não respondeu
            ServerError: se o AS retornou uma mensagem de erro
            InvalidResponseError: se a resposta do AS veio em um formato inesperado
        """
        try:
            AS.sign_up(client_id, password)
        except (ServerDownError, ServerError, InvalidResponseError) as e:
            # log(e)
            raise

    def acquire_new_ticket(self, service_id, requested_time):
        """Obtem um ticket para uso de um determinado serviço.
        
        Contacta o Serviço de Autenticação (AS) e o Serviço de
        Concessão de Tickets (TGS) para obter um ticket que
        garante acesso ao serviço escolhido.
       
        Args:
            service_id (str): ID do serviço desejado
            requested_time (str): Tempo solicitado

        Returns:
            autorizated_time (str): Tempo concedido.

        Throws:
            ServerDownError: se o AS ou o TGS estiverem offline
            ServerError: se o AS ou o TGS retornar uma mensagem
                de erro
            InvalidResponseError: se a resposta do AS ou do TGS
                veio em um formato inesperado
        """

        client_key = Crypto.generate_key_from_password(
            self.current_user['password'],
            salt=self.current_user['client_id'].encode()
        )

        # Poderiam também ser parâmetros que o cliente escolhe,
        # mas eu decidi implementar desse jeito por ser mais
        # simples:
        #   * Como a aplicação cliente vai contactar o TGS logo
        #     em seguida, o TGT só precisa valer por alguns
        #     segundos/minutos
        #   * Só tem um TGS, então não faz sentido deixar o
        #     cliente falar qual ele quer
        tgt_requested_time = datetime.strftime(datetime.now() + timedelta(minutes=5), '%d/%m/%Y %H:%M')
        tgs_id = 'TGS'

        print("Autenticando no Serviço de Autenticação (AS)... ")
        try:
            tgs_ticket, tgs_session_key = AS.request_ticket_granting_ticket(
                client_id=self.current_user['client_id'],
                client_key=client_key,
                requested_time=tgt_requested_time,
                service_id=tgs_id
            )
        except (ServerDownError, ServerError, InvalidResponseError) as e:
            # log(e)
            raise

        print("Obtendo ticket de acesso através do Serviço de Concessão de Tickets (TGS)...")
        try:
            service_ticket, service_session_key, autorized_time = TGS.request_access_ticket(
                client_id=self.current_user['client_id'],
                service_id=service_id,
                requested_time=requested_time,
                ticket=tgs_ticket,
                session_key=tgs_session_key
            )
        except (ServerDownError, ServerError, InvalidResponseError) as e:
            # log(e)
            raise

        print(f"Salvando ticket...")
        self._save_ticket(
            ticket=service_ticket,
            session_key=service_session_key,
            autorized_time=autorized_time,
            client_id=self.current_user['client_id'],
            service_id=service_id
        )

        return autorized_time

    def use_service(self, service_id, ticket, session_key):
        """Tenta acessar um serviço com o ticket especificado
        
        Args:
            service_id (str): ID do serviço a ser contactado
            ticket (bytes): Ticket de acesso
            session_key (bytes): Chave de sessão para
                comunicação com o serviço
            
        Returns:
            str: resposta do serviço

        Throws:
            ServerDownError: se o serviço estiver offline
            ServerError: se o serviço retornar uma mensagem de erro
            InvalidResponseError: se a resposta do serviço veio
                em um formato inesperado
            UnknownServiceError: se o método foi chamado para um
                serviço desconhecido
        """

        if service_id == 'service1':
            # Depende do serviço, aqui é só um exemplo
            request = "Send me something back"

            try:
                response = Service.request(
                    client_id=self.current_user['client_id'],
                    ticket=ticket,
                    session_key=session_key,
                    request=request
                )
            except (ServerDownError, ServerError, InvalidResponseError) as e:
                # log(e)
                raise
        else:
            raise UnknownService()

        return response

    def get_available_tickets(self, service_id=None):
        """Retorna os tickets disponíveis para o usuário atual
        
        Args:
            service_id (str, optional): ID de serviço para filtrar
                os resultados. Se não for especificado, serão 
                retornados todos os tickets salvos
        
        Returns:
            arr: Lista de tickets
        """

        tickets = self._load_all_tickets()

        # O mais correto aqui seria retornar somente os tickets
        # que aquele cliente obteve.
        #     No entanto, como é só um trabalho, é interessante
        # testar o que aconteceria se um cliente tentasse usar
        # um ticket de outro.
        #     Esse método retorna todos os tickets para um
        # determinado serviço, mas o serviço só vai permitir
        # o acesso se o ID que está no ticket bater com o
        # ID do cliente que está tentando acessar
        if service_id:
            available_tickets = [ticket for ticket in tickets
                                 if ticket['serviceId'] == service_id]
        else:
            available_tickets = tickets

        return available_tickets
    

    def _save_ticket(self, ticket, session_key, autorized_time, client_id, service_id):
        """Salva um ticket para uso futuro
        
        Args:
            ticket (bytes): O ticket em si, obtido do TGS
            session_key (bytes): Chave de sessão que deve ser usada em
                conjunto com este ticket
            autorized_time (str): Tempo autorizado para uso
            client_id (str): ID do cliente que obteve o ticket
            service_id (str): ID do serviço a que o ticket garante acesso
        """

        tickets = self._load_all_tickets()

        tickets.append({
            'ticket': ticket.decode(),
            'sessionKey': session_key.decode(),
            'autorizedTime': autorized_time,
            'clientId': client_id,
            'serviceId': service_id
        })

        self._save_all_tickets(tickets)

    def _load_all_tickets(self):
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
    
    def _save_all_tickets(self, tickets):
        """Persiste todos os tickets"""

        TICKETS_PATH = pkg_resources.resource_filename('kerberos_client', 'data/tickets.json')

        with open(TICKETS_PATH, 'w') as f:
            json.dump(tickets, f, indent=2)