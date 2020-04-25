
SRC_ELF_SIGN    := elf_sign.c
SRC_SIGN_TARGET := sign_target.c
SRC_PARSE       := parse.c
SRC = $(SRC_ELF_SIGN) $(SRC_SIGN_TARGET) $(SRC_PARSE)

ELF_SIGN     := elf-sign
SIGN_TARGETT := sign-target
PARSE        := parse
EXEC = $(ELF_SIGN) $(SIGN_TARGETT) $(PARSE)

all: $(SRC)
	cc -o $(ELF_SIGN) $(SRC_ELF_SIGN) -lcrypto -lelf
	cc -o $(SIGN_TARGETT) $(SRC_SIGN_TARGET)
	cc -o $(PARSE) $(SRC_PARSE)

clean: 
	$(RM) $(EXEC)
	$(RM) $(SIGN_TARGETT).*
	$(RM) *.out
	$(RM) *.sig