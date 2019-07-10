#!/bin/bash

mkdir RCDCap-Ninja-build

cd RCDCap-Ninja-build

cmake -DCMAKE_BUILD_TYPE=Debug -G "Ninja" ../

ninja -j 12

cd ..

echo "======"
echo "DONE (Debug)"
