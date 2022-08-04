#!/usr/bin/env bash

set -e

MODULE="${1}"

if [ -z "${MODULE}" ]; then
  echo "Use: .compile.sh <module dir>"
  exit 1
fi
if [ ! -d "${PWD}/${MODULE}" ]; then
  echo "Module dir not found!"
  exit 1
fi

curl -sLO "https://github.com/fbelavenuto/arpl/raw/main/PLATFORMS"

while read PLATFORM KVER; do
  DIR="${KVER:0:1}.x"
  [ ! -d "${PWD}/${MODULE}/${DIR}" ] && continue
  if ! grep -q "$i" "${PWD}/${MODULE}/.exclude" 2>/dev/null; then
    docker run -u 1000 --rm -it -v "${PWD}/${1}/${DIR}":/input -v "${PWD}/../${i}":/output fbelavenuto/syno-compiler compile-module ${PLATFORM}
  fi
done < PLATFORMS
