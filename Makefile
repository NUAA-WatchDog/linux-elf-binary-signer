
SRC_ELF_SIGN    := elf_sign.c
SRC = $(SRC_ELF_SIGN)

ELF_SIGN     := elf-sign
EXEC = $(ELF_SIGN)

all: $(SRC)
	cc -o $(ELF_SIGN) $(SRC_ELF_SIGN) -lcrypto
	./$(ELF_SIGN).signed sha256 certs/kernel_key.pem certs/kernel_key.pem $(ELF_SIGN)

clean: 
	$(RM) $(EXEC)
	$(RM) .*_sig
	$(RM) *.old
	$(RM) -r test/prev/prev_test
	$(RM) hello-*
