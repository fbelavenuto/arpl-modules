#!/usr/bin/env bash

SOURCE="/home/fabio/download/linux-firmware"
while read L; do
  FN="${SOURCE}/${L}"
  if [ -e "${FN}" ]; then
    mkdir -p "`dirname firmware/${L}`"
    cp "${FN}" "firmware/${L}"
  else
    echo "Missing ${FN}"
  fi
done < <(find -name \*.ko -exec sh -c '/sbin/modinfo {} | grep ^firmware' \; | awk '{print$2}')
