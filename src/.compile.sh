#!/usr/bin/env bash

set -e

if [ ! -d "${PWD}/${1}" ]; then
  echo "Module dir not found!"
  exit 1
fi

for i in bromolow-3.10.108 apollolake-4.4.180 broadwell-4.4.180 broadwellnk-4.4.180 denverton-4.4.180 geminilake-4.4.180 v1000-4.4.180
do
  PLATFORM=`echo ${i} | cut -d'-' -f1`
  KVER=`echo ${i} | cut -d'-' -f2`
  DIR="${KVER:0:1}.x"
  if [ -d "${PWD}/${1}/${DIR}" ]; then
    if ! grep -q "$i" "${PWD}/${1}/.exclude" 2>/dev/null; then
      docker run -u 1000 --rm -it -v "${PWD}/${1}/${DIR}":/input -v "${PWD}/../${i}":/output fbelavenuto/syno-compiler compile-module ${PLATFORM}
    fi
  fi
done
