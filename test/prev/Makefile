
SRC = prev_test.c

EXEC = prev-test

ELF_SIGN = elf-sign

all: $(SRC)
	cc -o $(EXEC) $(SRC)
	../../$(ELF_SIGN).signed sha256 ../../certs/kernel_key.pem ../../certs/kernel_key.pem $(EXEC)

clean: 
	$(RM) $(EXEC)
	$(RM) .*_sig
	$(RM) *.old
	$(RM) -r prev_test/
