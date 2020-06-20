
SRC_ELF_SIGN    := elf_sign.c
SRC_SIGN_TARGET := sign_target.c
SRC = $(SRC_ELF_SIGN) $(SRC_SIGN_TARGET)

ELF_SIGN     := elf-sign
SIGN_TARGET  := sign-target
EXEC = $(ELF_SIGN) $(SIGN_TARGET)

all: $(SRC)
	cc -o $(ELF_SIGN) $(SRC_ELF_SIGN) -lcrypto
	cc -o $(SIGN_TARGET) $(SRC_SIGN_TARGET)
	./$(ELF_SIGN).signed sha256 certs/kernel_key.pem certs/kernel_key.pem $(ELF_SIGN)

clean: 
	$(RM) $(EXEC)
	$(RM) $(SIGN_TARGET).*
	$(RM) $(ELF_SIGN)
	$(RM) .*_sig
	$(RM) *.old
	$(RM) -r test/prev_test
