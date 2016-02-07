 htwtxt – hosted twtxt server
============================

Rationale
---------

"twtxt" is a protocol and client (<https://github.com/buckket/twtxt>) for
decentralized microblogging. Users are expected to provide their feeds as plain
text files with URLs accessible over the Internet. "htwtxt" is a web server to
host and grow such text files for users without trivial access to their own web
space.

Clone, build, run
-----------------

With htwtxt written in Go, the following instructions expect a Go development
environment with the go tool (<https://golang.org/cmd/go/>) installed, and the
$GOPATH set:

    git clone https://github.com/plomlompom/htwtxt $GOPATH/src/
    go get htwtxt
    mkdir ~/htwtxt
    cp -R $GOPATH/src/htwtxt/templates ~/htwtxt
    cd ~/htwtxt
    $GOPATH/bin/htwtxt

This will build and start the server, and set up directories and files expected
by it below ~/htwtxt (or any other path you prefer instead of this).

Configuring port number and TLS
-------------------------------

By default, htwtxt serves unencrypted HTTP over port 8000. But the executable
accepts up to three optional arguments to change this:

    $GOPATH/bin/htwtxt [PORT] [CERTIFICATE] [KEY]

PORT is the port number to serve. CERTIFICATE and KEY are paths to the
certificate and key files needed to run htwtxt as a HTTPS server.

Copyright, license
------------------

htwtx (c) 2016 Christian Heller a.k.a. plomlompom

License: Affero GPL version 3, see ./LICENSE
