
class TimeValidator:
    @classmethod
    def requested_time_is_valid(cls, requested_time_str):
        """Verifica se o tempo requisitado está no formato certo"""
        
        try:
            requested_time = datetime.strptime(requested_time_str, '%d/%m/%Y %H:%M')
            return True
        except ValueError:
            return False