#!/bin/bash

cflags="-Wall -Wextra -Wno-unused -Werror -O3 -s"
cppflags="-Wall -Wextra -Wno-unused -Werror -O3 -s -std=gnu++17"
idir="-Iinclude"
macros=""
outfile="bin/mashro3"
src="src/packet.c"
srcpp="src/main.cpp"
obj="main.o packet.o res/ui.o res/png.o"
ldir=""
libs="-lpthread -lboost_thread"

function build_x86_64-linux {
export CC="gcc"

./res/glade2o.sh res/ui.o res/*.ui
./res/png2o.sh res/png.o res/*.png

gcc \
$(pcap-config --cflags) \
$cflags -c $idir $macros $src \

g++ \
$(pcap-config --cflags) \
$(pkg-config gtkmm-3.0 --cflags) \
$cppflags -c $idir $macros $srcpp \

mkdir -p bin

g++ \
-o ${outfile}_x86_64-linux $obj \
$(pcap-config --libs) \
$(pkg-config gtkmm-3.0 --libs) \
$ldir $libs

rm -f $obj
}

function build_i686-linux {
echo -n
}

function build_x86_64-w64 {
echo -n
}

function build_i686-w64 {
echo -n
}

CALLEEDIR=$PWD
cd "$(dirname "$0")"

case $1 in

"x86_64-linux") build_x86_64-linux;;
"i686-linux") build_i686-linux;;
"x86_64-w64") build_x86_64-w64;;
"i686-w64") build_i686-w64;;
""|"all")
build_x86_64-linux;
#    build_i686-linux;
#    build_x86_64-w64;
#    build_i686-w64;;

esac

cd "$CALLEEDIR"
