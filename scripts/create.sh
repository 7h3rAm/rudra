#!/usr/bin/env bash

[[ $# != 1 ]] && echo "USAGE: $0 <filename>" && exit 1 || filename="$1"
pbscript="python pb.py"
$pbscript -bc "$filename"
