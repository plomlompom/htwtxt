# htwtxt – hosted twtxt server

## Rationale

[*twtxt*](https://github.com/buckket/twtxt) is a protocol and client for
decentralized microblogging. Users are expected to provide their feeds as plain
text files with URLs accessible over the Internet. *htwtxt* is a web server to
host and grow such text files for users without trivial access to their own web
space.

## Online demo

A demo instance with frequent downtimes can be tested at
http://test.plomlompom.com:8000 – don't expect any of its feeds' URLs to be
stable. It's just for testing, and data frequently gets deleted.

## Setup and run

### Setup Go build environment

With htwtxt written in Go, the setup instructions below expect a Go development
environment – with a somewhat current [go tool](https://golang.org/cmd/go/)
installed, and a `$GOPATH` set. If your system does not have such an
environment, here's some hints on how to set it up:

    wget https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.5.3.linux-amd64.tar.gz
    export GOPATH=~/go
    export PATH=$PATH:/usr/local/go/bin

(You might want to add the last two lines to your `.bashrc` or whatever usually
initializes your environment variables. And you might want to replace the
package pulled by wget by whatever is the newest stable release of Go
available.)

### Clone, build, run

Once your Go build environment is ready, do this:

    git clone https://github.com/plomlompom/htwtxt $GOPATH/src/htwtxt
    go get htwtxt
    mkdir ~/htwtxt
    $GOPATH/bin/htwtxt

This will build and start the server, which will store login and feed data below
`~/htwtxt`. An alternate directory may be specified with the `--dir` flag.

## Tweaking

### Configuring port number and TLS

By default, htwtxt serves unencrypted HTTP over port 8000. But the executable
accepts the flag `--port` to provide an alternate port number, and the flags
`--cert` and `--key` to provide paths to an SSL certificate and key file to run
htwtxt as an HTTPS server.

You might encounter the following issue when trying to set a low port number
(such as the HTTP standard 80, or the HTTPS standard 443):

    ListenAndServe: listen tcp :80: bind: permission denied

This is [a common privilege problem](http://stackoverflow.com/q/413807) and
[might be solved](http://stackoverflow.com/a/414258) bis this:

    sudo setcap 'cap_net_bind_service=+ep' $GOPATH/bin/htwtxt

### Changing HTML templates

By default, HTML templates are read out of `$GOPATH/src/htwtxt/templates/`. An
alternate directory can be given with the flag `--templates` (it should contain
template files of the same names as the default ones, however).

### Setting site owner contact info

The server serves a `/info` page (from the `info.html` template) that may
include the site owner's contact info, as given with the `--info` flag.

## Copyright, license

htwtxt (c) 2016 Christian Heller a.k.a. plomlompom

License: Affero GPL version 3, see `./LICENSE`
