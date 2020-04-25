#!/bin/bash

target=$1
section_name=$2
sig_file="sig.out"

if [ ! ${target} ]; then
	echo @@ Missing argument
	echo @@ Target ELF: $1
elif [ ! ${section_name} ]; then
	echo @@ Missing argument
	echo @@ Signature section name: $2
else
	echo @@ Signing for: ${target}
	elf-sign ${target} \
		sha256 certs/kernel_key.pem certs/kernel_key.pem\
		${sig_file} > /dev/null

	echo @@ Making a copy of ${target}: ${target}.sig
	cp ${target} ${target}.sig

	echo @@ Adding section for: ${target}.sig
	objcopy --add-section ${section_name}=${sig_file} \
		--set-section-flags ${section_name}=readonly \
		${target}.sig
	echo @@ Signature added to ${target}.sig

	rm ${sig_file}
fi