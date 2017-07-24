#!/usr/bin/env bash

[[ $# != 1 ]] && echo "USAGE: $0 <pasteid>" && exit 1 || pasteid="$1"
pbscript="python pb.py"
$pbscript -br $pasteid
