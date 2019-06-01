class TimeValidator:
    TGT_EXPIRATION_TIME_FORMAT = '%d/%m/%Y %H:%M'
    
    REQUESTED_TIME_FORMAT = '%d/%m/%Y %H:%M'

    @classmethod
    def tgt_expiration_time_is_valid(cls, tgt_expiration_time_str):
        """Verifica se o prazo de validade do TGT está no formato certo"""

        try:
            expiration_date = datetime.strptime(tgt_expiration_time_str, cls.TGT_EXPIRATION_TIME_FORMAT)
            return True
        except ValueError:
            return False

    @classmethod
    def requested_time_is_valid(cls, requested_time_str):
        """Verifica se o tempo requisitado está em um dos formatos válidos"""

        # O TGS implementado só trabalha com um formato de "tempo
        # de acesso": "dd/mm/yyyy HH:MM", que significa que o
        # cliente quer ou está autorizado a acessar o serviço até
        # essa data.
        # 
        # Caso fosse interessante, ele poderia ser aprimorado
        # para aceitar outras formas de os clientes especificarem
        # um tempo de acesso:
        #   Ex: Em um período específico --> "FROM 10:00 TO 22:00"
        #       Somente alguns dias --> "DAYS=[mon, tue, wed, thu, fri]"
        try:
            requested_time = datetime.strptime(requested_time_str, cls.REQUESTED_TIME_FORMAT)
            return True
        except ValueError:
            return False
