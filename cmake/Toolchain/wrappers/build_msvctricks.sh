#!/bin/bash
i686-w64-mingw32-g++ -O3 -fno-ident -fno-stack-protector -static msvctricks.cpp -municode -lshlwapi -o msvctricks.exe
