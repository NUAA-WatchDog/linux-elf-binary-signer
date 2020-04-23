#!/bin/bash

cc -o main main.c
cc -o elf-sign elf-sign.c -lelf -lcrypto

sig_file="sig.out"
section_name=".code_sig"

./elf-sign main sha256 kernel_key.pem kernel_key.pem $sig_file
objcopy --add-section $section_name=$sig_file --set-section-flags $section_name=readonly main