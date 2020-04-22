cc -o main main.c
cc -o elf-sign elf-sign.c -lelf -lcrypto

./elf-sign main sha256 kernel_key.pem kernel_key.pem