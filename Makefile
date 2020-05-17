
SRC_ELF_SIGN    := elf_sign.c
SRC_SIGN_TARGET := sign_target.c
SRC_PARSE       := parse.c
SRC = $(SRC_ELF_SIGN) $(SRC_SIGN_TARGET) $(SRC_PARSE)

ELF_SIGN     := elf-sign
SIGN_TARGET  := sign-target
PARSE        := parse
EXEC = $(ELF_SIGN) $(SIGN_TARGET) $(PARSE)

all: $(SRC)
	cc -o $(ELF_SIGN) $(SRC_ELF_SIGN) -lcrypto -lelf
	cc -o $(SIGN_TARGET) $(SRC_SIGN_TARGET)
	# cc -o $(PARSE) $(SRC_PARSE)
	# ./$(ELF_SIGN).signed $(ELF_SIGN) sha256 certs/kernel_key.pem certs/kernel_key.pem

clean: 
	$(RM) $(EXEC)
	$(RM) $(SIGN_TARGET).*
	$(RM) $(ELF_SIGN)
	$(RM) .*_sig
	$(RM) *.old
	$(RM) -r test/prev_test