#!/bin/bash

set -e

echo WITHOUT FURTHER MODIFICATION
echo THIS IS A REALLY BAD, THOROUGHLY INSECURE WAY TO SETUP HTWTXT.
echo YOU HAVE BEEN WARNED.
echo
echo SETTING UP SERVER KEY AND CERTIFICATE
cd $GOPATH/src/htwtxt
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out cert.pem -days 365
echo INSTALLING GO DEPENDENCIES
go get
KEY=MyTrulyBadDefaultKey
echo RUNNING WITH $KEY AS SESSIONSTORE KEY
KEY=$KEY go run main.go 8000 cert.pem server.key
