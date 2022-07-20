#!/usr/bin/env bash

set -e

for i in apollolake-4.4.180 broadwell-4.4.180 broadwellnk-4.4.180 bromolow-3.10.108 denverton-4.4.180 geminilake-4.4.180 v1000-4.4.180
do
  PLATFORM=`echo $i | cut -d'-' -f1`
  docker run -u 1000 --rm -it -v $PWD/$1/4.x:/input -v $PWD/../$i:/output fbelavenuto/syno-compiler compile-module $PLATFORM
done
docker run -u 1000 --rm -it -v $PWD/$1/3.x:/input -v $PWD/../$i:/output fbelavenuto/syno-compiler compile-module bromolow
