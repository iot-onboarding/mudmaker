#!/bin/sh
# Copyright 2017-2025 Eliot Lear
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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

