#!/bin/bash

mkdir RCDCap-Ninja-RelWithDebInfo-build

cd RCDCap-Ninja-RelWithDebInfo-build

cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -G "Ninja" ../

ninja -j 12

echo "======"
echo "DONE (RelWithDebInfo)"

cd ..
