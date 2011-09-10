#!/bin/sh

cd `dirname $0`
if [ ! -e CMakeLists.txt ] ; then echo "missing source directory"; exit -1; fi

rm -rf CMakeCache.txt CMakeFiles Makefile cmake_install.cmake

MODE=Release
case $1 in
	( --debug | -d ) MODE=Debug ;;
	( --help | -h) echo "script will configure using cmake. call with --debug or --release"; exit; ;;
esac

cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=$MODE
if [ $? -eq 0 ] ; then
  echo "all done, type make to build"
fi

