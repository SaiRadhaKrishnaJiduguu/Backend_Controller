#!/bin/bash

# loop & print a folder recursively,
print_folder_recurse() {
    for i in "$1"/*; do
        if [ -d "$i" ];then
            print_folder_recurse "$i"
        elif [ -f "$i" ]; then
            if [ ${i: -3} == ".py" ]; then
              echo $i
              pylint --disable=W0718,E0401,E0213,R0903,E1135,E1136,E0211,C0301,R1702,R0912,R0914,R0911,W0719,C0206,R0915,E0611 $i
            fi
        fi
    done
}

print_folder_recurse "."