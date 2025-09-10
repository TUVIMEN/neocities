class NeocitiesError(Exception):
    pass


class AuthenticationError(NeocitiesError):
    pass


class OpFailedError(NeocitiesError):
    pass


class FileNotFoundError(OpFailedError):
    pass


class RequestError(NeocitiesError):
    pass
