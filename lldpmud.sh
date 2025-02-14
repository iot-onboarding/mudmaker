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
# Usage: lldpmud {MURURL}

mudurl=$1 # see?

# let's do a bit of validation on this thing

echo $mudurl| egrep '^https://' > /dev/null 2>&1

if [ $? != 0 ]; then
  echo "0: invalid MUDURL $mudurl"
  echo "$0: correct form:  https://domain/..."
  exit
fi

odval=`echo -n $1 |od -A n -t x1 -w1024 | sed -e 's/^ //' -e 's/ /,/g'`

lldpcli=`which lldpcli`

if [ $? != 0 ]; then
  "$0: lldpcli not found"
  exit -1
fi

$lldpcli configure lldp custom-tlv add oui 00,00,5e subtype 01 oui-info $odval
 
