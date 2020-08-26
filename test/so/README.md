# Tests for Dynamic Linking

Created by : Mr Dk.

2020 / 08 / 26 16:15

---

There is a function `int test(int, int)` defined in `test.h` and implemented in `test.c`. It will be compiled as a shared object called `libtest.so`.

And a program in `so_test.c` will call this function, so the `so_test.c` should be compiled with `libtest.so`.

Use following command to compile the shared object and the `so-test` program:

```console
$ make
cc test.c -fPIC -shared -o libtest.so
cc so_test.c -L. -ltest -o so-test
```

Then, move the `libtest.so` to the library directory and then execute `ldconfig`. The library directory can be:

* `/lib/x86_64-linux-gnu/`
* `/usr/lib/x86_64-linux-gnu/`
* ...

Then, use `ldconfig` to refresh the dynamic linking cache. Finally, check the library by:

```console
$ sudo cp libtest.so /lib/x86_64-linux-gnu
$ sudo ldconfig
$ strings /etc/ld.so.cache | grep libtest 
libtest.so
/lib/x86_64-linux-gnu/libtest.so
```

When executing the `so-test` program, the `libtest.so` will be found by dynamic linker. The `libtest.so` can also be signed by `elf-sign`:

```console
$ ./elf-sign sha256 certs/kernel_key.pem certs/kernel_key.pem test/so/libtest.so
 --- 64-bit ELF file, version 1 (CURRENT), little endian.
 --- 24 sections detected.
 --- Section 0009 [.text] detected.
 --- Length of section [.text]: 237
 --- Signature size of [.text]: 465
 --- Writing signature to file: .text_sig
 --- Removing temporary signature file: .text_sig
```

---

