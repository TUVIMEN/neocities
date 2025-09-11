#!/usr/bin/env python
# by Dominik Stanisław Suchora <hexderm@gmail.com>
# License: GNU GPLv3

import os
from pathlib import Path
import hashlib
from typing import Generator, List
import itertools

import treerequests
import requests

from .errors import (
    AuthenticationError,
    OpFailedError,
    FileNotFoundError,
    RequestError,
)


def get_ext(fname: str) -> str:
    r = fname.rpartition(".")
    if r[1] != ".":
        return ""
    return r[2]


def sha1(data: str | bytes):
    if isinstance(data, str):
        data = data.encode()

    return hashlib.sha1(data).hexdigest()


def filesha1(path: str | Path):
    h = hashlib.sha1()

    with open(path, "rb") as f:
        while True:
            if data := f.read(1024 * 1024):
                h.update(data)
            else:
                break
    return h.hexdigest()


class Neocities:
    DOMAIN = "https://neocities.org/api"

    UPLOAD_CHUNK_SIZE = 32

    # ucurl -s 'https://github.com/neocities/neocities/raw/refs/heads/master/models/site.rb' | sed -n '/^ *VALID_EXTENSIONS = /{N;s/.*\n *//; s/^/"/;s/$/"/;s/ /",\n"/g;p;q}'
    VALID_EXTENSIONS = [
        "html",
        "htm",
        "txt",
        "text",
        "css",
        "js",
        "jpg",
        "jpeg",
        "png",
        "apng",
        "gif",
        "svg",
        "md",
        "markdown",
        "eot",
        "ttf",
        "woff",
        "woff2",
        "json",
        "geojson",
        "csv",
        "tsv",
        "mf",
        "ico",
        "pdf",
        "asc",
        "key",
        "pgp",
        "xml",
        "mid",
        "midi",
        "manifest",
        "otf",
        "webapp",
        "less",
        "sass",
        "rss",
        "kml",
        "dae",
        "obj",
        "mtl",
        "scss",
        "webp",
        "avif",
        "xcf",
        "epub",
        "gltf",
        "bin",
        "webmanifest",
        "knowl",
        "atom",
        "opml",
        "rdf",
        "map",
        "gpg",
        "resolveHandle",
        "pls",
        "yaml",
        "yml",
        "toml",
        "osdx",
        "mjs",
        "cjs",
        "ts",
        "glb",
        "py",
        "glsl",
    ]

    def __init__(self, **kwargs):
        settings = {"visited": False, "wait": 0.3, "timeout": 30, "failures": [400]}
        settings.update(kwargs)

        self.ses = treerequests.Session(
            requests,
            requests.Session,
            None,
            requesterror=RequestError,
            **settings,
        )

        self.username = ""
        self.password = ""
        self.api = ""

    def _call_api_request(self, path: str, auth: bool, method: str, kwargs) -> dict:
        if auth:
            if self.api != "":
                if kwargs.get("headers") is None:
                    kwargs["headers"] = {}
                kwargs["headers"]["Authorization"] = "Bearer " + self.api
            else:
                kwargs["auth"] = (self.username, self.password)

        return self.ses.json(self.DOMAIN + "/" + path, **kwargs, method=method)

    def _call_api(self, path: str, auth: bool = True, method="post", **kwargs) -> dict:
        r = self._call_api_request(path, auth, method, kwargs)
        if r["result"] == "success":
            return r
        if r["result"] == "error":
            etype = r["error_type"]
            message = r["message"]
            if etype == "invalid_auth":
                raise AuthenticationError(message)
            elif etype == "missing_files":
                raise FileNotFoundError(message)
            elif etype == "not_found":
                raise OpFailedError(message)
            else:
                raise OpFailedError(message)
        raise OpFailedError(r)

    def login(self, username: str = "", password: str = "", api: str = ""):
        """
        Sets authentication credentials.

        arg( api ) refers to api key, if empty both arg( username ) and arg( password ) have to be specified.
        """

        if api == "":
            if username == "":
                raise AuthenticationError("empty username")
            if password == "":
                raise AuthenticationError("empty password")
            self.username = username
            self.password = password
        else:
            if not self.valid_api(api):
                raise AuthenticationError("invalid api")
            self.api = api

    def login_from_env(self):
        if (api := os.getenv("NEOCITIES_API")) is not None:
            return self.login(api=api)

        username = os.getenv("NEOCITIES_USERNAME")
        password = os.getenv("NEOCITIES_PASSWORD")
        if username is not None and password is not None:
            self.login(username=username, password=password)

        raise ValueError("no environment variables for authentication set")

    @staticmethod
    def valid_api(api: str) -> bool:
        if len(api) != 32:
            return False

        api = api.lower()
        for i in api:
            if not i.isdigit() and (i < "a" or i > "f"):
                return False
        return True

    def key(self) -> str:
        """
        returns( api key for a user )
        """
        return self._call_api("key", method="get")["api_key"]

    def info(self, sitename="") -> dict:
        """
        Gets info of user's site or about arg( sitename ) if it's not empty.

        returns( Dictionary of site info )
        """

        params = None
        auth = True
        if sitename != "":
            auth = False
            params = {"sitename": sitename}

        return self._call_api("info", method="get", auth=auth, params=params)["info"]

    def list(self, paths: str | Path | List[str | Path] = "") -> List[dict]:
        """
        Lists file structure of site at arg( path ), if empty arg( path ) defaults to "/".

        return( List of dictionaries describing site's file sructure )
        """

        if isinstance(paths, str) or isinstance(paths, Path):
            paths = [paths]

        ret = []
        for path in paths:
            params = None
            if path != "":
                params = {"path": str(path)}

            ret.extend(self._call_api("list", method="get", params=params)["files"])
        return ret

    def delete(self, paths: str | List[str]):
        """
        Removes lists of paths from sites, if directory path is passed it'll be removed recursively.
        """

        if isinstance(paths, str):
            paths = [paths]

        if len(paths) == 0:
            return

        self._call_api("delete", data={"filenames[]": paths})

    def upload_hash(self, files: dict[str, str]) -> dict[str, bool]:
        """
        Checks if files on site have the same sha1 hash, this api is redundant since method( list ) already returns sha1 hashes for all files.

        arg( files ) is a dictionary representing files, where keys are file paths and values are suspected sha1 hashes.

        returns( Dictionary where keys are file paths and values are `True` if remote files have the same hash, otherwise `False` )
        """
        if len(files) == 0:
            return

        return self._call_api("upload_hash", data=files)["files"]

    def upload_hash_files(self, files: dict[str, str | Path]) -> dict[str, bool]:
        """
        Same as method( upload_hash ) but values of arg( files ) are paths of files from which sha1 hash will be calculated.
        """
        if len(files) == 0:
            return

        data = {str(i): filesha1(files[i]) for i in files}
        return self.upload_hash(data)

    @staticmethod
    def _file_allowed(path: str) -> bool:
        if not os.path.isfile(path):
            return False

        name = os.path.basename(path)
        ext = get_ext(name).lower()
        return ext in Neocities.VALID_EXTENSIONS

    @staticmethod
    def _get_files_from_dir(
        path: str | Path, follow_links: bool = False
    ) -> Generator[str]:
        for i in os.scandir(path):
            if not follow_links and i.is_symlink():
                continue
            if i.is_dir():
                yield from Neocities._get_files_from_dir(i.path)
            elif Neocities._file_allowed(i.path):
                yield i.path

    @staticmethod
    def _get_uploads_from_dir(
        path: str | Path, remote_path: str, follow_links: bool = False
    ) -> Generator[tuple[str, str]]:
        path = os.path.normpath(str(path)) + "/"
        for i in Neocities._get_files_from_dir(path, follow_links=follow_links):
            rel_path = i.removeprefix(path)
            rem_path = os.path.join(remote_path, rel_path)
            yield (rem_path, i)

    def _upload_files(
        self, paths: dict[str | Path, str], follow_links: bool
    ) -> Generator[tuple[str, str]]:
        files = {}
        for i in paths:
            key = str(i)
            val = paths[i]

            if files.get(val) is not None:
                continue

            if os.path.isdir(key):
                for j in self._get_uploads_from_dir(
                    key, val, follow_links=follow_links
                ):
                    if files.get(j[0]) is not None:
                        continue
                    files[j[0]] = j[1]
                    yield j
            elif self._file_allowed(key):
                files[val] = key
                yield (val, key)

    def upload_text(self, paths: dict[str, str | bytes]):
        """
        Uploads files from arg( paths ), where key is remote path and value is contents of file
        """
        if len(paths) == 0:
            return

        self._call_api("upload", files=paths)

    def upload(self, paths: dict[str | Path, str], follow_links: bool = False):
        """
        Uploads files from arg( paths ), where keys are local paths and values remote paths.

        If any local path is a directory,  multiple calls will be made to transfer all matching files under it.
        """
        if len(paths) == 0:
            return

        files = self._upload_files(paths, follow_links)

        for i in itertools.batched(files, self.UPLOAD_CHUNK_SIZE):
            fchunk = {j[0]: (j[1], open(j[1], "rb")) for j in i}
            self._call_api("upload", files=fchunk)

    # def create_directory(self, path: str):
    # """
    # Creates empty directory at arg( path ).
    # """
    # https://neocities.org/site/create_directory

    # def rename(self, prevpath: str | Path, newpath: str | Path):
    # """
    # Renames and moves file or directory at arg( prevpath ) to arg( newpath ).
    # """
    # https://neocities.org/site_files/rename

    def purge(self):
        """
        Removes everything from site, since `index.html` can't be removed it'll be replaced with empty file.
        """

        files = [i["path"] for i in self.list() if i["path"] != "index.html"]
        self.delete(files)

        self.upload_text({"index.html": b""})

    def _sync_local_files(
        self, path: str | Path, follow_links: bool
    ) -> set[tuple[str, str]]:
        path = path.removesuffix("/")
        for i in self._get_uploads_from_dir(path, "", follow_links=follow_links):
            hsum = filesha1(i[1])
            yield (hsum, i[1].removeprefix(path + "/"))

    def _sync_remote_files(self, files, path: str) -> dict[str, str]:
        for i in files:
            if i["is_directory"]:
                continue
            yield (i["sha1_hash"], i["path"].removeprefix(path + "/"))

    def _sync_empty_directories(
        self, remote_files, local_files, dest: str
    ) -> Generator[str]:
        directories = {
            i["path"].removeprefix(dest): False
            for i in remote_files
            if i["is_directory"]
        }
        for i in local_files:
            path = i[1]
            while (path := os.path.dirname(path)) != "" and path != "/":
                if directories.get(path) is not None:
                    directories[path] = True
        return (path for path in directories if not directories[path])

    def _sync_lists(
        self, source: str, dest: str, follow_links: bool
    ) -> tuple[List[str], dict[str, str]]:
        local_files = set(self._sync_local_files(source, follow_links))
        remote_files_all = self.list(dest)
        remote_files = set(self._sync_remote_files(remote_files_all, dest))

        to_delete = remote_files - local_files
        to_upload = local_files - remote_files
        to_delete = set(i[1] for i in to_delete)
        to_upload = set(i[1] for i in to_upload)
        to_delete -= to_upload

        for i in self._sync_empty_directories(remote_files_all, local_files, dest):
            to_delete.add(i)

        to_delete = [os.path.join(dest, i) for i in to_delete]
        to_upload = {os.path.join(source, i): os.path.join(dest, i) for i in to_upload}

        return to_delete, to_upload

    def sync(self, source: str | Path, dest: str = "", follow_links: bool = False):
        """
        Ensures that site structure is exactly the same as that under str( path ) directory. Files having the same hashes are not retransferred.
        """

        dest = dest.removeprefix("/")
        to_delete, to_upload = self._sync_lists(source, dest, follow_links)

        self.delete(to_delete)
        self.upload(to_upload, follow_links=follow_links)

    def _download_files(
        self, sources: str | List[str], dest: str | Path
    ) -> dict[str, str]:
        files = {}
        if isinstance(sources, str):
            sources = [sources]

        for i in sources:
            i.removeprefix("/")
            flist = self.list(i)
            if flist == []:
                files[os.path.basename(i)] = i
            else:
                for j in flist:
                    if j["is_directory"]:
                        continue
                    path = j["path"]
                    if path == i:
                        files[os.path.basename(path)] = path
                    else:
                        files[path.removeprefix(i).removeprefix("/")] = path

        return files

    def download(self, sources: str | List[str], dest: str | Path = ""):
        """
        Downloads site files from arg( sources ) to arg( dest ), arg( sources ) can be either a list of remote paths or just a string
        """

        files = self._download_files(sources, dest)

        sitename = self.info()["sitename"]
        url = "https://{}.neocities.org".format(sitename)

        for file in files:
            rpath = files[file]
            file = file.removeprefix("/")
            file = os.path.join(dest, file)

            os.makedirs(os.path.dirname(file), exist_ok=True)

            r = self.ses.get(url + "/" + rpath, stream=True)
            with open(file, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    f.write(chunk)
