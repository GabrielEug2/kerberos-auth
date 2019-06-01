
class ServerDownError(Exception):
    pass

class ServerError(Exception):
    pass

class ResponseDoesNotMatch(Exception):
    pass

class InvalidResponseError(Exception):
    pass

class UnknownService(Exception):
    pass