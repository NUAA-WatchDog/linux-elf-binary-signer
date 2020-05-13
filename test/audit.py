#!/usr/bin/env python3

"""Audit the cost of signature verification by VM logs."""

#
# Copyright (C) 2020, Jingtang Zhang <mrdrivingduck@gmail.com>.
# Copyright (C) 2020, Hua Zong.
#
# Licensed under MIT.
#

#
# Parse the result of vm execution into the structure.
# The target line is like: "[   44.257384] @@@./mount@@@790614".
#
# file: the VM log file.
# mapper: <ELF bin name, [time1, time2, ...]>
#
def parse_result(file, mapper):
    for line in file:
        line = line.strip("\n")
        tokens = line.split("@@@")
        if len(tokens) == 3:
            bin_name = tokens[1]
            exec_time = int(tokens[2])
            if bin_name.startswith("./") and not bin_name.endswith(".sh"):
                if not bin_name in mapper:
                    mapper[bin_name] = [];
                mapper[bin_name].append(exec_time)

#
# Audit the cost of signature verification for one binary.
#
# bin_name: the name of ELF binary.
# sv_result_arr: the execution time array of kernel with sv.
# no_sv_result_arr: the exection time array of kernel without sv.
#
def audit_sv_cost(bin_name, sv_result_arr, no_sv_result_arr):
    if len(sv_result_arr) != len(no_sv_result_arr):
        raise Exception("Execution time inconsistent.")
    no_sv_time = 0
    sv_time = 0
    for exec_time in sv_result_arr:
        sv_time += exec_time
    for exec_time in no_sv_result_arr:
        no_sv_time += exec_time
    
    print("-- ELF binary:", bin_name)
    print("---- SV-time: ", sv_time)
    print("---- NO-SV-time: ", no_sv_time)
    print("---- COST: ", sv_time / no_sv_time)

if __name__ == "__main__":
    no_sv_result = open("prev-test-no-sv.log")
    sv_result = open("prev-test.log")

    no_sv_audit = {}
    sv_audit = {}

    parse_result(no_sv_result, no_sv_audit)
    parse_result(sv_result, sv_audit)

    if len(sv_audit) != len(no_sv_audit):
        raise Exception("File format error.")

    for bin in no_sv_audit.keys():
        audit_sv_cost(bin, sv_audit[bin], no_sv_audit[bin])

    no_sv_result.close()
    sv_result.close()
