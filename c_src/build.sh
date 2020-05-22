#!/usr/bin/env sh
python3 setup.py build
mv build/lib*/* .
rm -r build
