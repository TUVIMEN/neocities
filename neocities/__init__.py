#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import sys

from .neocities import Neocities
from .errors import (
    NeocitiesError,
    AuthenticationError,
    OpFailedError,
    FileNotFoundError,
    RequestError,
)
from .cli import cli


def main():
    cli(sys.argv[1:] if sys.argv[1:] else ["-h"])
