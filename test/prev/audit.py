#!/usr/bin/env python3

"""Audit the cost of signature verification by VM logs."""

#
# Copyright (C) 2020, Jingtang Zhang <mrdrivingduck@gmail.com>.
# Copyright (C) 2020, Hua Zong.
#
# Licensed under MIT.
#

import sys

#
# Parse the result of vm execution into the structure.
# The target line is like: "uname done in 3526416 μs.".
#
# @file: the VM log file.
# @mapper: <ELF bin name, exec time>
#
def parse_result(file, mapper):
    for line in file:
        line = line.strip("\n")
        tokens = line.split(" ")
        if len(tokens) == 5:
            bin_name = tokens[0]
            exec_time = int(tokens[3])
            if tokens[4].endswith("μs."):
                mapper[bin_name] = exec_time

#
# Script entry.
#
# @since 2020/09/01
#
# @argv[1]: VM log without signature verification.
# @argv[2]: VM log with signature verification.
#
if __name__ == "__main__":
    no_sv_result = open(sys.argv[1]) # no-sv-res
    sv_result = open(sys.argv[2]) # sv-res

    # @key: ELF binary name
    # @value: Array of execute time.
    # e.g. <"./ls", 12321312(μs)>, <...>, ...
    no_sv_audit = {}
    sv_audit = {}

    # Parse the result from VM log file.
    parse_result(no_sv_result, no_sv_audit)
    parse_result(sv_result, sv_audit)

    if len(sv_audit) != len(no_sv_audit):
        raise Exception("File format error.")

    # Calculate the cost.
    for bin in no_sv_audit.keys():
        print("-- ELF binary:", bin)
        print("---- SV-time: ", sv_audit[bin])
        print("---- NO-SV-time: ", no_sv_audit[bin])
        print("---- COST: ", sv_audit[bin] / no_sv_audit[bin])

    no_sv_result.close()
    sv_result.close()
