#!/bin/sh
#
# a simple script to sign a mud file.
# we assume the cert files are in this directory.

certdir=.

mudfile=$1

if [ x$mudfile = x ]; then
 echo "Usage: $0 {mudfile}"
 exit
fi

sigfile=`echo $mudfile| sed 's/.json/.p7s/'`

if [ x$sigfile = x$mudfile ]; then
    sigfile=${mudfile}.p7s
fi

echo "File to be signed: " $mudfile
echo "Signature file: " $sigfile
/bin/echo -n "Signing..."
openssl cms -sign -signer $certdir/signer.pem -in $mudfile -inkey $certdir/signer.key -binary -outform DER  -certfile $certdir/intermediate.pem -out $sigfile
if [ $? != 0 ]; then
   exit -1
fi
echo "[ok]"
echo "Verifying..."

openssl cms -verify -in $sigfile -inform DER  -content $mudfile -binary \
                 -CAfile $certdir/root.pem -purpose any -out /dev/null

