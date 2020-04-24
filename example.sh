#!/bin/bash

sig_file="sig.out"
section_name=".code_sig"
target="sign-target"

echo @@ Signing for: ${target}
elf-sign ${target} \
		sha256 kernel_key.pem kernel_key.pem\
		${sig_file} > /dev/null

echo @@ Making a copy of ${target} with signature: ${target}.sig
cp ${target} ${target}.sig

echo @@ Adding section for: ${target}.sig
objcopy --add-section ${section_name}=${sig_file} \
        --set-section-flags ${section_name}=readonly\
        ${target}.sig
echo @@ Signature added to ${target}.sig

rm ${sig_file}