
import pkg_resources
import json
from datetime import datetime, timedelta

from kerberos_client.crypto import Crypto
from kerberos_client.communication.as_client import AS
from kerberos_client.communication.tgs_client import TGS
from kerberos_client.communication.service1_client import Service
from kerberos_client.exceptions import (ServerDownError,
                                        ServerError,
                                        InvalidResponseError,
                                        ResponseDoesNotMatch,
                                        UnknownService)

class KerberosClient:
    """Cliente de um sistema de autenticação Kerberos."""

    def __init__(self):
        self.current_user = None

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

    def acquire_new_ticket(self, client_id, password, service_id, requested_time):
        """Obtem um ticket para uso de um determinado serviço.
        
        Contacta o Serviço de Autenticação (AS) e o Serviço de
        Concessão de Tickets (TGS) para obter um ticket que
        garante acesso ao serviço escolhido.
       
        Args:
            client_id (str): ID do cliente que está solicitando o ticket
            client_key (bytes): Senha do cliente que está solicitando o ticket
            service_id (str): ID do serviço desejado
            requested_time (str): Tempo solicitado

        Returns:
            autorizated_time (str): Tempo concedido.

        Throws:
            ServerDownError: se não foi possível se conectar ao AS ou ao TGS
            ServerError: se o AS ou o TGS retornaram uma mensagem de erro
            ResponseDoesNotMatch: se a resposta do AS ou do TGS não 
                corresponde ao pedido
            InvalidResponseError: se a resposta do AS ou do TGS veio
                em um formato inesperado
        """

        # Salt determinístico para obter a mesma chave que o 
        # AS salvou quando o cliente se registrou
        client_key = Crypto.generate_key_from_password(password, salt=client_id.encode())

        # Poderiam ser parâmetros que o cliente escolhe, mas eu 
        # decidi implementar desse jeito para simplificar:
        #   * Como a aplicação cliente vai contactar o TGS logo
        #     em seguida, o TGT só precisa valer por alguns
        #     segundos/minutos
        #   * Só tem um TGS, então não faz sentido deixar o
        #     cliente falar qual ele quer
        tgt_requested_time = datetime.strftime(datetime.now() + timedelta(minutes=5), '%d/%m/%Y %H:%M')
        tgs_id = 'TGS'

        print("Autenticando no Serviço de Autenticação (AS)... ")
        try:
            tgt, tgs_session_key = AS.request_ticket_granting_ticket(
                client_id=client_id,
                client_key=client_key,
                requested_time=tgt_requested_time,
                service_id=tgs_id
            )
        except (ServerDownError, ServerError, ResponseDoesNotMatch, InvalidResponseError) as e:
            # log(e)
            raise

        print("Obtendo ticket de acesso através do Serviço de Concessão de Tickets (TGS)...")
        try:
            access_ticket, service_session_key, autorized_time = TGS.request_access_ticket(
                client_id=client_id,
                service_id=service_id,
                requested_time=requested_time,
                ticket=tgt,
                session_key=tgs_session_key
            )
        except (ServerDownError, ServerError, ResponseDoesNotMatch, InvalidResponseError) as e:
            # log(e)
            raise

        print(f"Salvando ticket...")
        self._save_ticket(
            ticket=access_ticket,
            session_key=service_session_key,
            autorized_time=autorized_time,
            service_id=service_id,
            client_id=client_id
        )

        return autorized_time

    def use_service(self, client_id, service_id, ticket, session_key):
        """Tenta acessar um serviço com o ticket especificado
        
        Args:
            client_id (str): ID do cliente que está tentando acessar
                o serviço
            service_id (str): ID do serviço a ser contactado
            ticket (bytes): Ticket de acesso
            session_key (bytes): Chave de sessão para comunicação
                com o serviço
            
        Returns:
            str: resposta do serviço

        Throws:
            ServerDownError: se o serviço estiver offline
            ServerError: se o serviço retornar uma mensagem de erro
            ResponseDoesNotMatch: se a resposta do AS ou do TGS não 
                corresponde ao pedido
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
                    client_id=client_id,
                    ticket=ticket,
                    session_key=session_key,
                    request=request
                )
            except (ServerDownError, ServerError, InvalidResponseError, ResponseDoesNotMatch) as e:
                # log(e)
                raise
        else:
            raise UnknownService(service_id + " não é um serviço conhecido")

        return response
    
    def get_available_tickets(self, client_id, service_id=None):
        """Retorna os tickets disponíveis para o cliente em questão
        
        Args:
            client_id (str): ID do cliente que quer ver os tickets disponíveis
            service_id (str, optional): ID de serviço para filtrar
                os resultados
        
        Returns:
            arr: Lista de tickets
        """

        tickets = self._load_all_tickets()

        # O mais correto aqui seria retornar somente os tickets
        # que esse mesmo cliente obteve. No entanto, como é só
        # um trabalho, achei interessante testar o que aconteceria
        # se um cliente tentasse usar um ticket de outro.
        # 
        # (Um cliente pode tentar usar qualquer um dos tickets
        # salvos, o serviço só vai aceitar se o ID que está 
        # escrito no ticket bater com o ID de quem está 
        # tentando acessar)
        if service_id:
            available_tickets = [ticket for ticket in tickets
                                 if ticket['serviceId'] == service_id]
        else:
            available_tickets = tickets

        return available_tickets
    

    def _save_ticket(self, ticket, session_key, autorized_time, service_id, client_id):
        """Salva um ticket para uso futuro
        
        Args:
            ticket (bytes): O ticket em si, obtido do TGS
            session_key (bytes): Chave de sessão que deve ser usada em
                conjunto com este ticket
            autorized_time (str): Tempo no qual o ticket será aceito pelo
                serviço
            service_id (str): ID do serviço a que o ticket garante acesso
            client_id (str): ID do cliente que obteve o ticket
        """

        tickets = self._load_all_tickets()

        # O certo aqui seria salvar o ticket, a chave de sessão e
        # o ID do serviço a que o ticket dá acesso, de uma forma que
        # somente o cliente que obteve o ticket pudesse recuperá-lo
        # e usá-lo mais tarde (criptografar com a chave simétrica 
        # desse cliente, por exemplo)
        #
        # Como é só um trabalho, achei interessante salvar os tickets
        # de um jeito que fosse possível testar o que aconteceria 
        # se um cliente tentasse usar um ticket de outro.
        tickets.append({
            'ticket': ticket.decode(),
            'sessionKey': session_key.decode(),
            'autorizedTime': autorized_time,
            'serviceId': service_id,
            'clientId': client_id
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