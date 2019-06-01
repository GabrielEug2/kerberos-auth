import re

class TimeValidator:
    REQUESTED_TIME_FORMAT = 'UNTIL: %d/%m/%Y %H:%M'

    @classmethod
    def requested_time_is_valid(cls, requested_time_str):
        """Verifica se o tempo requisitado está no formato certo"""

        try:
            requested_time = datetime.strptime(requested_time_str, cls.REQUESTED_TIME_FORMAT)
            return True
        except ValueError:
            return False