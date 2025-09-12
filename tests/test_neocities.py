#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import os
import sys
import hashlib

from neocities import (
    Neocities,
    NeocitiesError,
    AuthenticationError,
    OpFailedError,
    FileNotFoundError,
    RequestError,
)

neo = Neocities()
neo.login()

os.chdir(os.path.dirname(__file__) + "/site-files")


def filesha1(path):
    h = hashlib.sha1()

    with open(path, "rb") as f:
        while True:
            if data := f.read(1024 * 1024):
                h.update(data)
            else:
                break
    return h.hexdigest()


def test_key():
    key = neo.key()
    assert neo.valid_apikey(key)


def check_info(info):
    assert isinstance(info, dict)

    assert len(info["sitename"]) > 0

    views = info["views"]
    assert isinstance(views, int) and views >= 0

    hits = info["hits"]
    assert isinstance(hits, int) and hits >= 0

    assert len(info["created_at"])

    assert info.get("domain", -1) != -1

    assert len(info["created_at"]) == 31
    assert len(info["last_updated"]) == 31
    assert isinstance(info["tags"], list)


def test_info():
    check_info(neo.info())
    check_info(neo.info(sitename="tuvimen"))


def check_list_element(el):
    assert isinstance(el, dict)

    assert len(el["path"]) > 0

    assert isinstance(el["is_directory"], bool)

    assert len(el["created_at"]) == 31
    assert len(el["updated_at"]) == 31

    if not el["is_directory"]:
        size = el["size"]
        assert isinstance(size, int)
        assert size >= 0

        sha1 = el["sha1_hash"]
        assert len(sha1) == 40
        for i in sha1:
            assert i.isdigit() or (i >= "a" and i <= "f")


def check_list(ls):
    assert isinstance(ls, list)
    for i in ls:
        check_list_element(i)


def check_dir_empty(ls):
    assert len(ls) == 1
    el = ls[0]
    assert el["path"] == "index.html"
    assert el["size"] == 0


def empty_site():
    neo.purge()
    ls = neo.list()
    check_list(ls)
    check_dir_empty(ls)


def check_files(path, elements):
    files = neo.list(path)
    check_list(files)

    found = 0
    for i in elements:
        for j in files:
            if j["path"] != i["path"]:
                continue
            assert j["is_directory"] == i["is_directory"]
            if not j["is_directory"]:
                assert j["size"] == i["size"]
                assert j["sha1_hash"] == i["sha1_hash"]
            found += 1
    assert found == len(files)


def test_upload():
    empty_site()
    neo.upload(
        {
            "bomb.py": "/python/bomba.py",
            "res/depth/green-gray.png": "favicon.png",
            "./file.html": "/index.html",
            "res/depth": "/grant",
        }
    )
    check_files(
        "/",
        [
            {
                "path": "favicon.png",
                "is_directory": False,
                "size": 2125576,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "40b813d822e3f071eed56d0ceb518b22904204c2",
            },
            {
                "path": "grant",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
            },
            {
                "path": "grant/green-gray.png",
                "is_directory": False,
                "size": 2125576,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "40b813d822e3f071eed56d0ceb518b22904204c2",
            },
            {
                "path": "grant/purple-yellow.webp",
                "is_directory": False,
                "size": 104104,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "a36c32684e890df69ba1eb52a8d543b8373627a3",
            },
            {
                "path": "grant/red-black.jpg",
                "is_directory": False,
                "size": 589411,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "804d08a38d3e1e6dc56243d9be2cbd0ecdadc4ad",
            },
            {
                "path": "index.html",
                "is_directory": False,
                "size": 757,
                "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "c5e731edee82d40acd491957f6bf44cf0d337322",
            },
            {
                "path": "python",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
            },
            {
                "path": "python/bomba.py",
                "is_directory": False,
                "size": 218,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "a02636f8ad8bdc1550d338487c0c89459cd4f89c",
            },
        ],
    )

    neo.delete(["/python", "favicon.png"])
    check_files(
        "/",
        [
            {
                "path": "grant",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
            },
            {
                "path": "grant/green-gray.png",
                "is_directory": False,
                "size": 2125576,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "40b813d822e3f071eed56d0ceb518b22904204c2",
            },
            {
                "path": "grant/purple-yellow.webp",
                "is_directory": False,
                "size": 104104,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "a36c32684e890df69ba1eb52a8d543b8373627a3",
            },
            {
                "path": "grant/red-black.jpg",
                "is_directory": False,
                "size": 589411,
                "created_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "804d08a38d3e1e6dc56243d9be2cbd0ecdadc4ad",
            },
            {
                "path": "index.html",
                "is_directory": False,
                "size": 757,
                "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:57:39 -0000",
                "sha1_hash": "c5e731edee82d40acd491957f6bf44cf0d337322",
            },
        ],
    )


def test_upload_text():
    empty_site()
    neo.upload_text(
        {
            "index.html": "<html><body>S</body></html>",
            "posts/ar/main.md": b"# header\n\ntext",
        }
    )
    check_files(
        "/",
        [
            {
                "path": "index.html",
                "is_directory": False,
                "size": 27,
                "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
                "updated_at": "Fri, 12 Sep 2025 19:07:57 -0000",
                "sha1_hash": "cceb5b08d3a78fa2f7213b9f513045fc7c1a6f9c",
            },
            {
                "path": "posts",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 19:07:57 -0000",
                "updated_at": "Fri, 12 Sep 2025 19:07:57 -0000",
            },
            {
                "path": "posts/ar",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 19:07:57 -0000",
                "updated_at": "Fri, 12 Sep 2025 19:07:57 -0000",
            },
            {
                "path": "posts/ar/main.md",
                "is_directory": False,
                "size": 14,
                "created_at": "Fri, 12 Sep 2025 19:07:57 -0000",
                "updated_at": "Fri, 12 Sep 2025 19:07:57 -0000",
                "sha1_hash": "ac9ad32aea16b70019548f66c0fe28d155611a97",
            },
        ],
    )

    neo.download(["posts/ar", "index.html"], "y")
    assert filesha1("y/index.html") == "cceb5b08d3a78fa2f7213b9f513045fc7c1a6f9c"
    assert filesha1("y/ar/main.md") == "ac9ad32aea16b70019548f66c0fe28d155611a97"

    os.remove("y/index.html")
    os.remove("y/ar/main.md")
    os.rmdir("y/ar")


def test_sync1():
    empty_site()
    neo.sync(".")
    check_files(
        "/",
        [
            {
                "path": "bomb.py",
                "is_directory": False,
                "size": 218,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "a02636f8ad8bdc1550d338487c0c89459cd4f89c",
            },
            {
                "path": "desc.md",
                "is_directory": False,
                "size": 820,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "7bb185c2d5a630ff1cb2c374e60bd407a2b0b297",
            },
            {
                "path": "file.html",
                "is_directory": False,
                "size": 757,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "c5e731edee82d40acd491957f6bf44cf0d337322",
            },
            {
                "path": "index.html",
                "is_directory": False,
                "size": 0,
                "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:34:29 -0000",
                "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            },
            {
                "path": "other.html",
                "is_directory": False,
                "size": 571,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "16b90ae7cd5fd56f62298ded7b9aa87b60d4e8a6",
            },
            {
                "path": "res",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
            },
            {
                "path": "res/black.png",
                "is_directory": False,
                "size": 619,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "8b614c1595fda0e4bba16bb1603c1c8c9daed1e5",
            },
            {
                "path": "res/depth",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
            },
            {
                "path": "res/depth/green-gray.png",
                "is_directory": False,
                "size": 2125576,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "40b813d822e3f071eed56d0ceb518b22904204c2",
            },
            {
                "path": "res/depth/purple-yellow.webp",
                "is_directory": False,
                "size": 104104,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "a36c32684e890df69ba1eb52a8d543b8373627a3",
            },
            {
                "path": "res/depth/red-black.jpg",
                "is_directory": False,
                "size": 589411,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "804d08a38d3e1e6dc56243d9be2cbd0ecdadc4ad",
            },
            {
                "path": "res/main.json",
                "is_directory": False,
                "size": 98,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "9d7e119b942bf9aeeaf7aa3eb39df3be5b425334",
            },
            {
                "path": "style.css",
                "is_directory": False,
                "size": 322,
                "created_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:38:30 -0000",
                "sha1_hash": "d9361b89bb5c529410d450c36295e34ae552b226",
            },
        ],
    )


def test_sync2():
    empty_site()
    neo.sync("res", "x/x/")
    check_files(
        "/",
        [
            {
                "path": "index.html",
                "is_directory": False,
                "size": 0,
                "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:34:29 -0000",
                "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            },
            {
                "path": "x",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
            },
            {
                "path": "x/x",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
            },
            {
                "path": "x/x/black.png",
                "is_directory": False,
                "size": 619,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": "8b614c1595fda0e4bba16bb1603c1c8c9daed1e5",
            },
            {
                "path": "x/x/depth",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
            },
            {
                "path": "x/x/depth/green-gray.png",
                "is_directory": False,
                "size": 2125576,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": "40b813d822e3f071eed56d0ceb518b22904204c2",
            },
            {
                "path": "x/x/depth/purple-yellow.webp",
                "is_directory": False,
                "size": 104104,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": "a36c32684e890df69ba1eb52a8d543b8373627a3",
            },
            {
                "path": "x/x/depth/red-black.jpg",
                "is_directory": False,
                "size": 589411,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": "804d08a38d3e1e6dc56243d9be2cbd0ecdadc4ad",
            },
            {
                "path": "x/x/main.json",
                "is_directory": False,
                "size": 98,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": "9d7e119b942bf9aeeaf7aa3eb39df3be5b425334",
            },
        ],
    )
    check_files(
        "x/x/res",
        [
            {
                "path": "x/x/depth",
                "is_directory": True,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
            },
            {
                "path": "x/x/black.png",
                "is_directory": False,
                "size": 619,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": None,
            },
            {
                "path": "x/x/main.json",
                "is_directory": False,
                "size": 98,
                "created_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "updated_at": "Fri, 12 Sep 2025 18:45:54 -0000",
                "sha1_hash": None,
            },
        ],
    )


def test_upload_hash():
    empty_site()
    neo.upload({"desc.md": "x.md", "other.html": "y/x/z.html"})

    r = neo.upload_hash(
        {
            "x.md": "7bb185c2d5a630ff1cb2c374e60bd407a2b0b297",
            "y/x/z.html": "9d7e119b942bf9aeeaf7aa3eb39df3be5b425334",
        }
    )
    assert r == {"x.md": True, "y/x/z.html": False}

    r = neo.upload_hash_files({"x.md": "style.css", "y/x/z.html": "other.html"})
    assert r == {"x.md": False, "y/x/z.html": True}

    empty_site()
