

def parse_result(file, mapper):
    for line in file:
        line = line.strip("\n")
        tokens = line.split("@@@")
        if len(tokens) == 3:
            if tokens[1].startswith("./") and not tokens[1].endswith(".sh"):
                if not tokens[1] in mapper:
                    mapper[tokens[1]] = [];
                mapper[tokens[1]].append(tokens[2])



no_sv_result = open("prev-test-no-sv.log")
sv_result = open("prev-test.log")

no_sv_audit = {}
sv_audit = {}

parse_result(no_sv_result, no_sv_audit)
for key in no_sv_audit.keys():
    print(key)
    print(len(no_sv_audit[key]))

no_sv_result.close()
sv_result.close()