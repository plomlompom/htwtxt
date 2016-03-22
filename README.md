# htwtxt – hosted twtxt server

## Rationale

[*twtxt*](https://github.com/buckket/twtxt) is a protocol and client for
decentralized microblogging. Users are expected to provide their feeds as plain
text files with URLs accessible over the Internet. *htwtxt* is a web server to
host and grow such text files for users without trivial access to their own web
space.

## Features

- individual twtxt feeds mapped to user accounts with password-protected write
  access
- no sessions, no cookies: few POST-writable resources (feeds, account data)
  expect credentials, which to store between requests if desired is up to the
  user / browser
- twtxt messages can be written via a HTML form in a web browser or via an API
- account registration may be open to the public, or (default) closed (with the
  site operator adding new accounts manually)
- users may add e-mail addresses and optional security questions to their
  accounts to use for a password reset mechanism (if enabled by site operator)
- HTTPS / TLS support (if paths to key and certificate files are provided)
- all HTML+CSS is read from a templates directory, which can be freely chosen at
  server start so as to ease customization of the interface
 
## Online demo

A demo instance with frequent downtimes and public sign-up can be tested at
<http://test.plomlompom.com:8000> (don't expect any of its feeds' URLs to be
stable; it's just for testing, and data frequently gets deleted). A somewhat
more conservatively managed instance can be found at
<http://htwtxt.plomlompom.com:80/>.

## Docker image

A docker image maintained by the htwtxt user buckket can be found here:
<https://hub.docker.com/r/buckket/htwtxt/>

## Setup and run

### Setup Go build environment

With htwtxt written in Go, the setup instructions below expect a Go development
environment – with a somewhat current [go tool](https://golang.org/cmd/go/)
installed, and a `$GOPATH` set. (Note that the golang package of version 1.3.3
that is part of Debian Jessie is a bit too old already.) If your system does not
have such an environment, here's some hints on how to set it up:

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

### Writing twtxt messages via API

Using htwtxt from a web browser for purposes such as writing a twtxt message
should be self-explanatory (just use the HTML form on the start page). But it's
also possible to write new messages directly to a twtxt feed via a `POST`
request to `/feeds`. Just provide appropriate values for the data fields `name`
and `password` (your login) and `twt` (the message to append). Here's a command
line example utilizing the curl tool:

    curl -X POST -d 'name=foo' -d 'password=bar' -d 'twt=Hi there.' \
    http://test.plomlompom.com:8000/feeds

## Tweaking

### Configure port number and TLS

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

### Public or closed sign-up

By default, sign up / account creation is not open to the web-browsing public.
The `--signup` flag must be set explicitely to change that. Alternatively, new
accounts can be added by starting the program with the `--adduser` flag,
followed by an argument of the form `NAME:PASSWORD`.

### Set site owner contact info

The server serves a `/info` page (from the `info.html` template) that may
include the site owner's contact info, as given with the `--contact` flag.

### Activate password reset mails

Feed owners may add e-mail addresses to their login data to authenticate
themselves to the site operator and receive password reset links when requested.
The password reset mechanism by mail is inactive by default. To activate it, a
set of flags `--mailserver`, `--mailport`, `--mailuser` must be set to describe
a SMTP server and its login from which to send password reset mails to users'
mail addresses. (The site operator will be prompted for his SMTP login password
on program start.) Whether this mechanism is trustworthy or not is up to the
site operator's imagination. Users may set up optional security questions to be
posed on the password reset links they enable by setting their mail address.

### Change HTML templates

By default, HTML templates are read out of `$GOPATH/src/htwtxt/templates/`. An
alternate directory can be given with the flag `--templates` (it should contain
template files of the same names as the default ones, however).

## Copyright, license, version

htwtxt (c) 2016 Christian Heller a.k.a. [plomlompom](http://www.plomlompom.de),
with template design input by [Kai Kubasta](http://kaikubasta.de).

License: Affero GPL version 3, see `./LICENSE`

Current version number: 1.0.6
