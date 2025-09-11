#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3


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
