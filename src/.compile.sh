#!/usr/bin/env bash

set -e

VER="7.1"

###############################################################################
function compile-module() {
  echo
  if [ ! -d "${PWD}/${1}" ]; then
    echo "Module dir not found!"
    exit 1
  fi
  echo -e "Compiling \033[7m${1}\033[0m..."
  while read PLATFORM KVER; do
    DIR="${KVER:0:1}.x"
    [ ! -d "${PWD}/${1}/${DIR}" ] && continue
    grep -q "${PLATFORM}-${KVER}" "${PWD}/${1}/.exclude" 2>/dev/null && continue
    docker run --rm -t -v "${PWD}/${1}/${DIR}":/input -v "${PWD}/../${PLATFORM}-${KVER}":/output fbelavenuto/syno-toolkit:${PLATFORM}-${VER} compile-module
  done < PLATFORMS
}

curl -sLO "https://github.com/fbelavenuto/arpl/raw/main/PLATFORMS"

if [ $# -ge 1 ]; then
  for A in $@; do
    compile-module ${A}
  done
else
  while read D; do
    MODULE=`basename ${D}`
    [ "${MODULE:0:1}" = "." ] && continue
    compile-module ${MODULE}
  done < <(find -maxdepth 1 -type d)
fi
