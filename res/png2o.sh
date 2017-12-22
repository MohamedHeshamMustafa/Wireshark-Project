#!/bin/bash

DST_FILE="$1"
shift

F="#include <stddef.h>
"
for SRC_FILE in $@
do
    VAR_NAME="${SRC_FILE##*/}"
    VAR_NAME="${VAR_NAME%.*}"
    F+="const size_t ${VAR_NAME}_size = $(stat -c%s $SRC_FILE);"$'\n'
    F+="const char *const $VAR_NAME = \\"$'\n'
    T=$(od -t x1 "$SRC_FILE" | sed -r 's/^[0-9]*//;s/ /\\x/g;s/(.*)/"\1" \\/')
    F+="$T"
    F+=$'\n;\n\n'
done

if [ "$CC" == "" ]
then
    CC="gcc"
fi

"$CC" -x c -c -o "$DST_FILE" - <<< "$F"
