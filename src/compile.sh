#!/usr/bin/env bash

set -e

TOOLKIT_VER="7.1"

if [ -f ../../arpl/PLATFORMS ]; then
  cp ../../arpl/PLATFORMS PLATFORMS
else
  curl -sLO "https://github.com/fbelavenuto/arpl/raw/main/PLATFORMS"
fi

echo -e "Compiling modules..."
while read PLATFORM KVER; do
  [ -n "$1" -a "${PLATFORM}" != "$1" ] && continue
  DIR="${KVER:0:1}.x"
  [ ! -d "${PWD}/${DIR}" ] && continue
  mkdir -p "${PWD}/../${PLATFORM}-${KVER}-temp"
  #docker run --rm -t -v "${PWD}/${1}/${DIR}":/input -v "${PWD}/../${PLATFORM}-${KVER}":/output \
  #  fbelavenuto/syno-toolkit:${PLATFORM}-${TOOLKIT_VER} compile-module
  docker run -u `id -u` --rm -t -v "${PWD}/${DIR}":/input -v "${PWD}/../${PLATFORM}-${KVER}-temp":/output \
    fbelavenuto/syno-compiler:${TOOLKIT_VER} compile-module ${PLATFORM}
  for M in `ls ${PWD}/../${PLATFORM}-${KVER}-temp`; do
    [ -f ~/src/pats/modules/${PLATFORM}/$M ] && \
      # original
      cp ~/src/pats/modules/${PLATFORM}/$M "${PWD}/../${PLATFORM}-${KVER}" || \
      # compiled
      cp ${PWD}/../${PLATFORM}-${KVER}-temp/$M "${PWD}/../${PLATFORM}-${KVER}"
  done
  rm -rf ${PWD}/../${PLATFORM}-${KVER}-temp
done < PLATFORMS
