#!/bin/bash

if [ ! -d bin ]; then
  mkdir bin
fi

g++ encryption.cpp legacy.cpp main.cpp -g -O3  -o bin/steamroller -I . -Llib -lm -Wl,-rpath,lib
