# linux-elf-binary-signer

🐧 Adding digital signature into ELF binary files.

Created by : Mr Dk.

2020 / 04 / 25 11:16

---

## About

A tool for protecting integrity of ELF binary files. It extracts the `.text` section of an ELF, and digitally signs it with *RSA* key. Finally, the program appends the signature data as another section.

For a [Linux kernel with signature verification module](https://github.com/NUAA-WatchDog/linux-kernel-elf-sig-verify-module), during the process of `execve()` system call, it will extract signed section and signature section, and verify the integrity of the ELF file. If it cannot pass the verification, the ELF will not be executed. The public key certificate for verification should be compiled with Linux kernel together.

## Build the Tool

To build the program, install the dependencies firstly:

```console
$ sudo apt install libssl-dev openssl
```

To check the result of signing, you also need following tools. But it is not necessary for the signing program.

```console
$ sudo apt install binutils
```

Then, build the tool through `make` command:

```console
$ make
cc -o elf-sign elf_sign.c -lcrypto
./elf-sign.signed sha256 certs/kernel_key.pem certs/kernel_key.pem elf-sign
 --- 64-bit ELF file, version 1 (CURRENT), little endian.
 --- 29 sections detected.
 --- [Library dependency]: libcrypto.so.1.1
 --- [Library dependency]: libc.so.6
 --- Section 0014 [.text] detected.
 --- Length of section [.text]: 10223
 --- Signature size of [.text]: 465
 --- Writing signature to file: .text_sig
 --- Removing temporary signature file: .text_sig
```

The `elf-sign.signed` ELF binary file has already been signed by the private key in `certs/kernel_key.pem`, so it can pass OS's verification to sign the newly built `elf-sign`. Then, with the signed `elf-sign`, you can sign other ELF binary files on your machine.

> If you want to generate your own key, you will need to sign the `elf-sign` binary by your own key on a kernel **without** signature verification, because the newly built `elf-sign` has no signature section. After signing, a signature section will be inserted and then it can be executed by a kernel **with** signature verification.
>
> If you just want to test the function, use the given `elf-sign.signed` to sign `elf-sign` after building (which will be done automatically by `Makefile` through `make` command). The `elf-sign.signed` has been signed with keys in `certs/kernel_key.pem` and it can be directly executed on a kernel with signature verification to sign your `elf-sign`.

## Usage

Show the helping information:

```console
$ ./elf-sign
Usage: elf-sign [-h] <hash-algo> <key> <x509> <elf-file> [<dest-file>]
  -h,         display the help and exit

Sign the <elf-file> to an optional <dest-file> with
private key in <key> and public key certificate in <x509>
and the digest algorithm specified by <hash-algo>. If no 
<dest-file> is specified, the <elf-file> will be backup to 
<elf-file>.old, and the original <elf-file> will be signed.
```

Sign an existing ELF file in repository:

```console
$ ./elf-sign sha256 certs/kernel_key.pem certs/kernel_key.pem \
    test/func/hello-gcc hello-gcc
 --- 64-bit ELF file, version 1 (CURRENT), little endian.
 --- 29 sections detected.
 --- [Library dependency]: libc.so.6
 --- Section 0014 [.text] detected.
 --- Length of section [.text]: 418
 --- Signature size of [.text]: 465
 --- Writing signature to file: .text_sig
 --- Removing temporary signature file: .text_sig
```

To check the result, use `readelf` or `objdump` tool from *binutils*:

```console
$ readelf -a hello-gcc
...
Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
...
  [29] .text_sig         PROGBITS         0000000000000000  000020c0
       00000000000001d1  0000000000000000   O       0     0     8
...
```

```console
$ objdump -s hello-gcc
...
Contents of section .text_sig:
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

## Test

Directory `test/func/` contains several simple ELF files **with different layout**, and we are happy to gather more files with different ELF layout.

`hello-gcc` is built from a very simple C program from GCC compiler:

```c
#include <stdio.h>

int main()
{
    printf("Hello world\n");
    return 0;
}
```

`hello-golang` is built from a very simple [Golang](https://golang.org/) program from Golang compiler:

```go
package main

import "fmt"

func main() {
    fmt.Println("Hello world!")
}
```

You can see the different layouts through `readelf -S`. The `elf-sign` program should support both of the layouts. And we are looking for more different ELF layouts.

## Generate Keys

### Generate Keys By Yourself

Firstly, configure some basic information of the key in `certs/x509.genkey`:

```
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = WatchDog
CN = ELF verification
emailAddress = mrdrivingduck@gmail.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

Then, generate the key through `openssl` command:

```console
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

This is the file for signing a signature, containing not only private key but also public key certificate. Also, the file should be compiled with kernel as a built-in key for signature verification.

### Generate Keys Through *Let's Encrypt*

See the website of [*Let's Encrypt*](https://letsencrypt.org/) and use [*Certbot*](https://certbot.eff.org/) to generate private key and public key certificate.

---

## Contributors

<a href="https://github.com/NUAA-WatchDog/linux-elf-binary-signer/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=NUAA-WatchDog/linux-elf-binary-signer" />
</a>

Made with [contributors-img](https://contributors-img.web.app).

## License

Copyright © 2020, Jingtang Zhang, Hua Zong. ([MIT License](LICENSE))

---

