import re

class TimeManager:
    EXPIRATION_DATE_REGEX = '\d{2}/\d{2}/\d{4} \d{2}:\d{2}'

    @classmethod
    def tgt_expiration_date_is_valid(cls, tgt_expiration_date_str):
        """Verifica se o prazo de validade do TGT está no formato certo"""

        try:
            expiration_date = datetime.strptime(tgt_expiration_date_str, '%d/%m/%Y %H:%M')
            return True
        except ValueError:
            return False

    @classmethod
    def expiration_date_str_to_date(cls, tgt_expiration_date_str):
        return datetime.strptime(tgt_expiration_date_str, '%d/%m/%Y %H:%M')

    @classmethod
    def requested_time_is_valid(cls, requested_time):
        """Verifica se o tempo requisitado está em um formato válido"""

        # O TGS poderia aceitar outras formas de o cliente
        # especificar um tempo solicitado:
        #   Ex: Em horários específicos --> "FROM 10:00 TO 22:00"
        #       Somente alguns dias --> "DAYS=[mon, tue, wed, thu, fri]"
        if re.match(cls.EXPIRATION_DATE_REGEX, requested_time):
            return True
        else:
            return False

    @classmethod
    def compute_autorized_time(cls, requested_time):
        """Computa o tempo que será autorizado ao cliente
        
        Args:
            requested_time (str): Tempo solicitado
        
        Returns:
            str: Tempo autorizado
        """

        # Dependendo de como são os serviços, poderia ter alguma
        # lógica de autorização. 
        #   Ex: acesso a salas --> somente um cliente pode usar
        #       de cada vez. Se já foi concedido este período para
        #       outro cliente, autoriza só a parte do tempo que
        #       não dá conflito, ou então não autoriza nada
        #
        # Como esse não é o foco do trabalho, esse TGS é bonzinho:
        # sempre autoriza o tempo que o cliente pediu.
        autorized_time = requested_time

        return autorized_time
