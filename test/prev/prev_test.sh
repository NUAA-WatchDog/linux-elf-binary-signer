#!/bin/bash

mkdir prev_test || (echo "cleaning"; rm -r prev_test; mkdir prev_test)
cd prev_test

target=$1 # From cmd parameter
# targets=("cp" "df" "echo" "false" "grep" "kill" "less" "ls" "mkdir" \
#     "mount" "mv" "rm" "rmdir" "tar" "touch" "true" "umount" "uname" )
exec_count=$2

echo
cp /bin/${target} ./
../../../elf-sign.signed sha256 \
    ../../../certs/kernel_key.pem ../../../certs/kernel_key.pem ./${target} > /dev/null

echo "*** Executing signed version of ${target} for ${exec_count} times."
for ((i = 0; i < ${exec_count}; i++))
do
    ./${target} > /dev/null 2>&1
done

echo "*** ${target} done."
