htwtxt – hosted twtxt server
============================

Rationale
---------

[*twtxt*](https://github.com/buckket/twtxt) is a protocol and client for
decentralized microblogging. Users are expected to provide their feeds as plain
text files with URLs accessible over the Internet. *htwtxt* is a web server to
host and grow such text files for users without trivial access to their own web
space.

Clone, build, run
-----------------

With htwtxt written in Go, the following instructions expect a Go development
environment with [the go tool](https://golang.org/cmd/go/) installed, and the 
`$GOPATH` set:

    git clone https://github.com/plomlompom/htwtxt $GOPATH/src/htwtxt
    go get htwtxt
    mkdir ~/htwtxt
    $GOPATH/bin/htwtxt

This will build and start the server, which will store login and feed data below
`~/htwtxt`. An alternate directory may be specified with the `--dir` flag.

Configuring port number and TLS
-------------------------------

By default, htwtxt serves unencrypted HTTP over port 8000. But the executable
accepts the flag `--port` to provide an alternate port number, and the flags
`--cert` and `--key` to provide paths to an SSL certificate and key file to run
htwtxt as an HTTPS server.

Copyright, license
------------------

htwtxt (c) 2016 Christian Heller a.k.a. plomlompom

License: Affero GPL version 3, see `./LICENSE`
