# neocities

A python api for neocities.org

# Installation

    pip install neocities-neo

# Usage

## CLI

```
usage: neocities [-h] [-u USERNAME] [-p PASSWORD] [-a API KEY] [-w TIME] [-W TIME] [-r NUM]
                   [--retry-wait TIME] [--force-retry] [-m TIME] [-k] [-L] [-A UA] [-x DICT]
                   [-H HEADER] [-b COOKIE] [-B BROWSER]
                   {key,sync,info,list,delete,purge,upload,upload-raw,hash,download} ...

Tool for interacting with neocities.org

If credentials for authorization are not passed through arguments, they'll be read from
$NEOCITIES_API or $NEOCITIES_USERNAME and $NEOCITIES_PASSWORD environment variables.

General:
  -h, --help            Show this help message and exit
  -u, --username USERNAME
                        Specify username for authentication
  -p, --password PASSWORD
                        Specify password for authentication
  -a, --api API KEY     Specify api key for authentication

subcommands:
  {key,sync,info,list,delete,purge,upload,upload-raw,hash,download}
    key                 get api key
    sync                ensure the same file structure on site
    info                get info about site
    list                list files on site
    delete              remove files recursively from site
    purge               remove all files from site
    upload              upload files to site
    upload-raw          upload files to site
    hash                check if files on site have the same sha1 hash
    download            download files from site recusively

Request settings:
  -w, --wait TIME       Sets waiting time for each request
  -W, --wait-random TIME
                        Sets random waiting time for each request to be from 0 to TIME
  -r, --retries NUM     Sets number of retries for failed request to NUM
  --retry-wait TIME     Sets interval between each retry
  --force-retry         Retry no matter the error
  -m, --timeout TIME    Sets request timeout
  -k, --insecure        Ignore ssl errors
  -L, --location        Allow for redirections, can be dangerous if credentials are passed in
                        headers
  -A, --user-agent UA   Sets custom user agent
  -x, --proxies DICT    Set requests proxies dictionary, e.g. -x
                        '{"http":"127.0.0.1:8080","ftp":"0.0.0.0"}'
  -H, --header HEADER   Set curl style header, can be used multiple times e.g. -H 'User: Admin'
                        -H 'Pass: 12345'
  -b, --cookie COOKIE   Set curl style cookie, can be used multiple times e.g. -b 'auth=8f82ab'
                        -b 'PHPSESSID=qw3r8an829'
  -B, --browser BROWSER
                        Get cookies from specified browser e.g. -B firefox
```

Each subcommand also has it's own `--help` message.

### key

Get a api key from username and password login

```shell
KEY=$(neocities --username USER --password PASS key)
```

This key can be passed through `--api` option or `$NEOCITIES_API` environment variable

```shell
neocities --api $KEY list /

export NEOCITIES_API="$KEY"
neocities list /
```

### info

Get info about site in json, passing without site's name requires to be logged in and displays info about your site.

```shell
neocities info
```

```json
{
  "sitename": "tuvimen",
  "views": 4226,
  "hits": 7052,
  "created_at": "Thu, 30 Jan 2025 17:42:37 -0000",
  "last_updated": "Thu, 11 Sep 2025 08:58:21 -0000",
  "domain": null,
  "tags": [
    "programming"
  ]
}
```

If site's name is given no authentication is required

```shell
neocities info tuvimen
```

### list

Return a list of site's files, if no path is given it defaults to `/`. Getting list of `/` always returns recursive tree of the whole site, this happens only for this path.

```shell
neocities list
```

Multiple paths can be queried

```shell
neocities list /projects /resources/css
```

Size and modification date can be printed along path when `-l` is specified, `-h` changes size into human readable format e.g. `2.2M`, `85.4K`

```shell
neocities list -lh /
```

Results can be returned as json

```
neocities list --json /
```

If path leads to a file no information is returned, this undesired behaviour comes from neocities api

```shell
neocities list /info.html
```

### sync

Ensure that site has the exact same files as under the given path, if not specified the path defaults to current directory.

```shell
neocities sync my-site-to-be-synced
```

This removes all files on site that aren't in path and upload files that are not on site or have different checksum. If directories have the same contents nothing gets transferred.

Note that this option doesn't log any changes so it might appear stuck, even though it uploads files.

This command can also sync individual directories on site

```shell
neocities sync ./static /static
```

### purge

Remove all files on site, since `/index.html` is protected it'll get replaced by empty file.

```shell
neocities purge
```

There's no warning or confirmation for using this command, if you type it by mistake everything disappears.


### delete

Removes files or directories recursively, `/` cannot be deleted

```shell
neocities delete /unwanted-file.html /old-directory/
```

### upload

Upload files or directories to remote, empty directories won't get created since there's no api for that.

```shell
neocities upload index.html posts/ /
```

Upload `list.html` to `/list2.html`

```shell
neocities upload list.html /list2.html
```

Even if directories on site don't exist they'll get created if uploaded file is in it

```shell
neocities upload file.html /a/b/c/d/e/f/g/h/f.html
```

Files with extensions not allowed by neocities will be ignored even if explicitly given in arguments.

### download

Download files and directories from site to local directory

```shell
neocities download /index.html /projects/ ./local-dir
```

### upload-raw

Upload files or directories where every following argument is it's remote destination

```shell
neocities upload-raw index.html /index.html static/css/ /css
```

Compared to `upload` subcommand, this allows to transfer more complex directory structures with only one request.

### hash

Check if files are the same as on remote, each remote file path has to be followed by local file path. Directories cannot be passed. Remote files that are different will be returned.

```shell
neocities hash /index.html ./static/index.html /res/favicon.ico static/res/favicon-different.ico
```

outputs

```shell
/res/favicon.ico
```

## Library

### importing and initializing

```python
from neocities import (
    neocities,
    NeocitiesError,
    RequestError,
    AuthorizationError,
    OpFailedError,
    FileNotFoundError
)

neo = Neocities(wait=0.8, timeout=60) # kwargs are passed to treerequests lib

try:
    neo.login(env=True) # login from environment variables
except AuthenticationError as e:
    print(repr(e), file=sys.stderr)
    sys.exit(1)

print(neo.list('/'))
```

### errors

All exceptions derive from `NeocitiesError`.

For authentication failure `AuthenticationError` is raised.

Any errors regarding http connection raise `RequestError`.

Failure to perform operation raises `OpFailedError`, `FileNotFoundError` derives from it.

### Neocities(**kwargs)

kwargs are passed to treerequests session object https://github.com/TUVIMEN/treerequests

### login(self, username: str = "", password: str = "", api: str = "", env: bool = False)

Sets authentication credentials.

arg( api ) refers to api key, if empty both arg( username ) and arg( password ) have to be specified.

If arg( env ) is set to True credentials are read from environment variables: $NEOCITIES_API, $NEOCITIES_USERNAME, $NEOCITIES_PASSWORD

### key(self) -> str

returns( api key for a user )

### info(self, sitename="") -> dict

Gets info of user's site or about arg( sitename ) if it's not empty.

Authentication is not required when arg( sitename ) is not empty.

returns( Dictionary of site info )

### list(self, paths: str | Path | List[str | Path] = "") -> List[dict]

Lists file structure of site at arg( path ), if empty arg( path ) defaults to "/".

return( List of dictionaries describing site's file sructure )

### delete(self, paths: str | List[str])

Removes arg( paths ) from site, if directory path is passed it'll be removed recursively.

### upload_hash(self, files: dict[str, str]) -> dict[str, bool]

Checks if files on site have the same sha1 hash, this api is redundant since method( list ) already returns sha1 hashes for all files.

arg( files ) is a dictionary representing files, where keys are file paths and values are suspected sha1 hashes.

returns( Dictionary where keys are file paths and values are `True` if remote files have the same hash, otherwise `False` )

### upload_hash_files(self, files: dict[str, str | Path]) -> dict[str, bool]

Same as method( upload_hash ) but values of arg( files ) are paths of files from which sha1 hash will be calculated.

### upload_text(self, paths: dict[str, str | bytes])

Uploads files from arg( paths ), where key is remote path and value is contents of file

### upload(self, paths: dict[str | Path, str], follow_links: bool = False)

Uploads files from arg( paths ), where keys are local paths and values remote paths.

If any local path is a directory,  multiple calls will be made to transfer all matching files under it.

### purge(self)

Removes everything from site, since `index.html` can't be removed it'll be replaced with empty file.

### sync(self, source: str | Path, dest: str = "", follow_links: bool = False)

Ensures that site structure is exactly the same as that under arg( source ) directory. Files having the same hashes are not retransferred.

### download(self, sources: str | List[str], dest: str | Path = "")

Downloads site files from arg( sources ) to arg( dest ), arg( sources ) can be either a list of remote paths or just a string.
