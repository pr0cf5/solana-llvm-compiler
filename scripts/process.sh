#!/bin/sh
cd `dirname $0`
cargo run -- --input-file $1 --output-file $2
objcopy --add-section .bpf=$1 --set-section-flags .bpf=readonly,alloc $2 $2
#ld -T bpf.ld -o $2 $2