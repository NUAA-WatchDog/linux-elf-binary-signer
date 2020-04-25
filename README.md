# linux-elf-binary-signer

🐧 Add digital signature into an ELF binary.

Created by : Mr Dk.

2020 / 04 / 25 11:16

---

## About

It is tool for protecting the integrity of an ELF binary. It extracts the `.text` section of an ELF, and sign it with **RSA** private key. Finally, append the signature as another section.

For a [Linux kernel with signature verification function](https://github.com/mrdrivingduck/kernel-with-elf-signature-verification), during the process of `execve()` system call, it will extract the signed section and the signature section, and verify the integrity of the ELF binary. If it cannot pass the verification, the ELF will not be executed. The certificate for verification should be compiled with Linux kernel together.

## Sign an ELF Binary

Firstly, install the dependencies:

```bash
$ sudo apt install libssl-dev libelf-dev binutils openssl
```

Then, compile and test the tool by:

```bash
$ make
cc -o elf-sign elf_sign.c -lcrypto -lelf
cc -o sign-target sign_target.c
cc -o parse parse.c
```

```bash
$ ./elf-sign sign-target sha256 certs/kernel_key.pem certs/kernel_key.pem
sign-target: 64-bit ELF object
29 sections detected.
Section 0014 .text
Code segment length: 418
Buffer size: 418
Writing signature to: .text_sig
Removing .text_sig
```

To check the result, use `readelf` or `objdump`:

```bash
$ readelf -a sign-target
...
Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
...
  [26] .code_sig         PROGBITS         0000000000000000  00001039
       00000000000001dd  0000000000000000           0     0     1
...
```

```bash
$ objdump -s sign-target
...
Contents of section .code_sig:
 0000 308201cd 06092a86 4886f70d 010702a0  0.....*.H.......
 0010 8201be30 8201ba02 0101310d 300b0609  ...0......1.0...
 0020 60864801 65030402 01300b06 092a8648  `.H.e....0...*.H
 0030 86f70d01 07013182 01973082 01930201  ......1...0.....
 0040 01306e30 56311130 0f060355 040a0c08  .0n0V1.0...U....
 0050 57617463 68446f67 31193017 06035504  WatchDog1.0...U.
 0060 030c1045 4c462076 65726966 69636174  ...ELF verificat
 0070 696f6e31 26302406 092a8648 86f70d01  ion1&0$..*.H....
 0080 09011617 6d726472 6976696e 67647563  ....mrdrivingduc
 0090 6b40676d 61696c2e 636f6d02 144879f3  k@gmail.com..Hy.
...
```

It means the tools work fine.

## Generate Private Key

Configure some basic information of the key in `certs/x509.genkey`:

```
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
#O = WatchDog
CN = ELF verification
#emailAddress = mrdrivingduck@gmail.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

Then, generate the key through `openssl` command:

```bash
$ cd certs
$ openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 \
    -config x509.genkey -outform PEM
    -out kernel_key.pem -keyout kernel_key.pem
Generating a RSA private key
........+++++
........................................+++++
writing new private key to 'kernel_key.pem'
-----
$ cd ..
```

This is the file for signing a signature. Also, the file should be compiled with kernel to become a built-in key for signature verification.

## License

Copyright © Jingtang Zhang, 2020. ([MIT License](LICENSE))

---

