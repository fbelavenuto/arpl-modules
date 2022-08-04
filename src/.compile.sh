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
  grep -q "${PLATFORM}-${KVER}" "${PWD}/${MODULE}/.exclude" 2>/dev/null && continue
  docker run -u 1000 --rm -it -v "${PWD}/${MODULE}/${DIR}":/input -v "${PWD}/../${PLATFORM}-${KVER}":/output fbelavenuto/syno-compiler compile-module ${PLATFORM}
done < PLATFORMS
