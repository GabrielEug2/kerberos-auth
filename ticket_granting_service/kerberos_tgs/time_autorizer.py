
class TimeAutorizer:
    @classmethod
    def compute_autorized_time(cls, requested_time):
        """Computa o tempo que será autorizado ao cliente
        
        Args:
            requested_time (str): Tempo solicitado
        
        Returns:
            str: Tempo autorizado
        """

        # Dependendo de como são os serviços, poderia ter alguma
        # lógica de autorização aqui. 
        #   Ex: acesso a salas --> somente um cliente pode usar
        #       de cada vez. Se já foi concedido um período para
        #       um cliente, outros que pedirem acesso depois não
        #       devem receber um ticket de acesso
        #
        # Como esse não é o foco do trabalho, esse TGS é bonzinho:
        # sempre autoriza o tempo que o cliente pediu.
        autorized_time = requested_time

        return autorized_time
