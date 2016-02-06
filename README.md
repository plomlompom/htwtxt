Quick and dirty hack of a server for hosted twtxt
=================================================

This provides a server to host twtxt feeds, if you want to provide users without
their own easily accessed webspace with a simple in-browser solution to twtxt.
(What is twtxt? See <https://github.com/buckket/twtxt>).

The whole thing is written in Go, building expects a working Go environment,
with $GOPATH set and the go tool installed.

INSTALLATION/USAGE:
-------------------

Copy this directory into your $GOPATH's src directory, i.e. to
$GOPATH/src/htwtxt – then run … 

    $ go get htwtxt

… then. with $key some secret session store key only you know, …

    $ KEY=$key go run $GOPATH/src/htwtxt/main.go

Optional arguments:

    $ KEY=$key go run $GOPATH/src/htwtxt/main.go [PORT] [CERTIFICATE] [SERVER_KEY]

PORT may be any desired port number to serve.

If you provide CERTIFICATE and SERVER KEY (both as file paths) as the second and
third argument, the server will run as a HTTPS server instead of a HTTP server.

A quick and dirty setup-and-run script can be found in ./bad-setup-and-run.sh –
an even dirtier one is found in ./bad-setup-and-run-https.sh …
