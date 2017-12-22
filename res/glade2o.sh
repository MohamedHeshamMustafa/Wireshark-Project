#!/bin/bash

DST_FILE="$1"
shift

F=""
for SRC_FILE in $@
do
    VAR_NAME="${SRC_FILE##*/}"
    VAR_NAME="${VAR_NAME%.*}"
    F+="const char *const $VAR_NAME = "
    T=$(sed -r 's|"|\\"|g; s|^|"|; s|$|\\n" \\|' "$SRC_FILE")
    if [ "$T" == "" ]
    then
        F+="\"\""
    else
        F+="$T"
    fi
    F+=$'\n;\n\n'
done

if [ "$CC" == "" ]
then
    CC="gcc"
fi

"$CC" -x c -c -o "$DST_FILE" - <<< "$F"
