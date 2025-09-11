#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import os
import sys
import argparse
import json
from datetime import datetime

import treerequests

from .neocities import Neocities
from .errors import (
    NeocitiesError,
    AuthenticationError,
    OpFailedError,
    FileNotFoundError,
    RequestError,
)


def valid_directory(directory):
    if directory != "":
        if not os.path.exists(directory):
            raise FileNotFoundError(directory)
        if not os.path.isdir(directory):
            raise Exception('"{}" is not a directory'.format(directory))
    return directory


def cmd_key(neo, args):
    print(neo.key())


def cmd_info(neo, args):
    print(json.dumps(neo.info(args.sitename), indent=2))


def hsize(size: int) -> str:
    modifiers = ["", "K", "M", "G", "T", "P", "Z", "Y"]
    mod = 0
    while size >= 1024:
        size /= 1024
        mod += 1
    assert mod < len(modifiers)
    return str(round(size, 2)) + modifiers[mod]


def to_mtime(date: str) -> str:
    return datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z").strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def cmd_list(neo, args):
    files = neo.list(args.paths)

    if args.json:
        print(json.dumps(files, separators=(",", ":")))
        return

    f = sys.stdout
    istty = sys.stdout.isatty()
    long = args.long

    max_size_l = 0
    max_mtime_l = 0
    for i in files:
        size = 4096 if i["is_directory"] else i["size"]
        size = hsize(size) if args.human_readable else str(size)
        max_size_l = max(max_size_l, len(size))
        i["size"] = size

        time = to_mtime(i["updated_at"])
        max_mtime_l = max(max_mtime_l, len(time))
        i["updated_at"] = time

    for i in files:
        isdir = i["is_directory"]
        if long:
            if istty:
                f.write("\x1b[33m")
            f.write(i["size"].rjust(max_size_l))
            if istty:
                f.write("\x1b[0m")
            f.write(" ")

            if istty:
                f.write("\x1b[32m")
            f.write(i["updated_at"].rjust(max_mtime_l))
            if istty:
                f.write("\x1b[0m")
            f.write(" ")

        if isdir and istty:
            f.write("\x1b[34;1m")

        f.write(i["path"])

        if isdir and istty:
            f.write("\x1b[0m")
        f.write("\n")


def valid_upload_paths(paths):
    i = 0
    pathsl = len(paths)
    ret = {}
    while i + 1 < pathsl:
        source = paths[i]
        dest = paths[i + 1]
        if not os.path.exists(source):
            raise FileNotFoundError("file at '{}' doesn't exist".format(source))
        if len(dest) == 0 or dest == "/":
            raise ValueError("destination cannot be empty '{}'".format(dest))
        ret[source] = dest
        i += 2

    if i < pathsl:
        raise ValueError("one of the files lacks destination")

    return ret


def cmd_upload(neo, args):
    paths = {}
    sources = args.sources
    sourcesl = len(sources)
    dest = args.dest or args.target_directory

    if sourcesl > 1:
        for i in sources:
            paths[i] = os.path.join(dest, os.path.basename(i))
    elif sourcesl == 1:
        source = sources[0]
        if dest[:1] == "/":
            paths[source] = os.path.join(dest, os.path.basename(source))
        else:
            files = neo.list(dest)
            if len(files) == 0:
                paths[source] = dest
            else:
                paths[source] = os.path.join(dest, os.path.basename(source))

    neo.upload(paths, follow_links=args.dereference)


def cmd_upload_raw(neo, args):
    paths = valid_upload_paths(args.paths)
    neo.upload(paths, follow_links=args.dereference)


def cmd_sync(neo, args):
    neo.sync(args.source, args.dest, follow_links=args.dereference)


def cmd_download(neo, args):
    neo.download(args.sources, args.dest)


def valid_hash_paths(paths):
    ret = {}
    i = 0
    pathsl = len(paths)
    while i + 1 < pathsl:
        ret[paths[i + 1]] = paths[i]
        i += 2

    if i < pathsl:
        raise ValueError("one of the files lacks source")
    return ret


def cmd_hash(neo, args):
    paths = valid_hash_paths(args.paths)
    r = neo.upload_hash_files(paths)
    for i in r:
        if not r[i]:
            print(i)


def cmd_delete(neo, args):
    neo.delete(args.paths)


def cmd_purge(neo, args):
    neo.purge()


def argparser():
    parser = argparse.ArgumentParser(
        description="Tool for interacting with neocities.org\n\nIf credentials for authorization are not passed through arguments, they'll be read from $NEOCITIES_API or $NEOCITIES_USERNAME and $NEOCITIES_PASSWORD environment variables.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    general = parser.add_argument_group("General")
    general.add_argument(
        "-h",
        "--help",
        action="help",
        help="Show this help message and exit",
    )
    general.add_argument(
        "-u",
        "--username",
        metavar="USERNAME",
        type=str,
        default="",
        help="Specify username for authentication",
    )
    general.add_argument(
        "-p",
        "--password",
        metavar="PASSWORD",
        type=str,
        default="",
        help="Specify password for authentication",
    )
    general.add_argument(
        "-a",
        "--api",
        metavar="API KEY",
        type=str,
        default="",
        help="Specify api key for authentication",
    )

    subparsers = parser.add_subparsers(title="subcommands", required=True)

    key_parser = subparsers.add_parser(
        "key", help="get api key", description="get api key"
    )
    key_parser.set_defaults(func=cmd_key)

    sync_parser = subparsers.add_parser(
        "sync",
        help="ensure the same file structure on site",
        description="Ensures that site structure is exactly the same as that under SOURCE. Files having the same hashes are not retransferred",
    )
    sync_parser.add_argument(
        "source", metavar="SOURCE", type=valid_directory, nargs="?", default=os.getcwd()
    )
    sync_parser.add_argument(
        "dest", metavar="DESTINATION", type=str, nargs="?", default=""
    )
    sync_parser.add_argument(
        "-H", "--dereference", help="follow symbolic links", action="store_true"
    )
    sync_parser.set_defaults(func=cmd_sync)

    info_parser = subparsers.add_parser(
        "info", help="get info about site", description="get info about site"
    )
    info_parser.add_argument(
        "sitename",
        metavar="SITENAME",
        type=str,
        default="",
        nargs="?",
    )
    info_parser.set_defaults(func=cmd_info)

    list_parser = subparsers.add_parser(
        "list",
        help="list files on site",
        description="list files on site",
        add_help=False,
    )
    list_parser.add_argument(
        "paths",
        metavar="PATH",
        type=str,
        default="",
        nargs="*",
    )
    list_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print results as json",
    )
    list_parser.add_argument(
        "-l",
        "--long",
        action="store_true",
        help="use a long listing format",
    )
    list_parser.add_argument(
        "-h",
        "--human-readable",
        action="store_true",
        help="print human readable sizes e.g. 2K, 2.53M, 4.1G",
    )
    list_parser.add_argument(
        "--help",
        action="help",
        help="Show this help message and exit",
    )
    list_parser.set_defaults(func=cmd_list)

    delete_parser = subparsers.add_parser(
        "delete",
        help="remove files recursively from site",
        description="remove files recursively from site",
    )
    delete_parser.add_argument(
        "paths",
        metavar="PATH",
        type=str,
        nargs="+",
    )
    delete_parser.set_defaults(func=cmd_delete)

    purge_parser = subparsers.add_parser(
        "purge",
        help="remove all files from site",
        description="remove all files from site",
    )
    purge_parser.set_defaults(func=cmd_purge)

    upload_parser = subparsers.add_parser(
        "upload",
        help="upload files to site",
        description="Upload files to site",
    )
    upload_parser.add_argument(
        "sources",
        metavar="SOURCE",
        type=str,
        nargs="+",
    )
    upload_parser.add_argument("dest", metavar="DEST", type=str)
    upload_parser.add_argument(
        "-H", "--dereference", help="follow symbolic links", action="store_true"
    )
    upload_parser.set_defaults(func=cmd_upload)

    upload_raw_parser = subparsers.add_parser(
        "upload-raw",
        help="upload files to site",
        description="Upload files to site, source and destination pairs can be repeated which allows to send entire directory structure with one request",
    )
    upload_raw_parser.add_argument(
        "paths",
        metavar="SOURCE DESTINATION",
        type=str,
        nargs="+",
    )
    upload_raw_parser.add_argument(
        "-H", "--dereference", help="follow symbolic links", action="store_true"
    )
    upload_raw_parser.set_defaults(func=cmd_upload_raw)

    hash_parser = subparsers.add_parser(
        "hash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="check if files on site have the same sha1 hash",
        description="Check if files on site have the same sha1 hash, source and destination pairs can be repeated which allows to send entire directory structure with one request\n\nOutputs files with different hashes",
    )
    hash_parser.add_argument(
        "paths",
        metavar="SOURCE DESTINATION",
        type=str,
        nargs="+",
    )
    hash_parser.set_defaults(func=cmd_hash)

    download_parser = subparsers.add_parser(
        "download",
        help="download files from site recusively",
        description="download files from site recusively",
    )
    download_parser.add_argument(
        "sources",
        metavar="SOURCE",
        nargs="+",
        default="",
        type=str,
    )
    download_parser.add_argument(
        "dest",
        metavar="DESTINATION",
        type=valid_directory,
    )
    download_parser.set_defaults(func=cmd_download)

    treerequests.args_section(parser)

    return parser


def neocities_create(args, login=True):
    neo = Neocities()
    treerequests.args_session(neo.ses, args)
    if login:
        neo.login(
            username=args.username, password=args.password, api=args.api, env=True
        )

    return neo


def cli(argv: list[str]):
    args = argparser().parse_args(argv)
    login = True
    if args.func == cmd_info and args.sitename != "":
        login = False
    try:
        neo = neocities_create(args, login=login)
        args.func(neo, args)
    except Exception as e:
        print(repr(e), file=sys.stderr)
