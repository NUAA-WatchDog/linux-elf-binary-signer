/**************************************************************************
 * 
 * Copyright (c) 2020, Jingtang Zhang, Hua Zong.
 * 
 * @author mrdrivingduck@gmail.com
 * @since 2020/04/20
 * 
 * ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>

int main(int argc , char **argv) {
    int fd;
    Elf *e;
    int version;

    Elf_Kind ek;
    Elf_Scn *scn;
    Elf_Data *data;
    GElf_Ehdr eher;
    GElf_Shdr shdr;
    char *name, *p, pc[4 * sizeof(char)];
    
    size_t n, shstrndx, sz;

    if (argc != 2)
        errx(EXIT_FAILURE , "usage: %s file -name", argv[0]);

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EXIT_FAILURE , "ELF library initialization " "failed: %s", elf_errmsg(-1));

    if ((fd = open(argv[1], O_RDONLY , 0)) < 0)
        err(EXIT_FAILURE , "open \%s\" failed", argv[1]);

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        errx(EXIT_FAILURE , "elf_begin() failed: %s.", elf_errmsg(-1));

    if (elf_kind(e) != ELF_K_ELF) {
        errx(EXIT_FAILURE, "\"%s\" is not an ELF object.", argv[1]);
    }
    
    // char *k;
    // ek = elf_kind(e);

    // switch (ek) {
    // case ELF_K_AR:
    //     k = "ar(1) archive";
    //     break;
    // case ELF_K_ELF:
    //     k = "elf object";
    //     break;
    // case ELF_K_NONE:
    //     k = "data";
    //     break;
    // default:
    //     k = "unrecognized";
    // }

    // if (gelf_getehdr(e, &ehdr) == NULL) {
    //     errx(EXIT_FAILURE, "getehdr() failed: %s.", elf_errmsg(-1));
    // }

    if ((version = gelf_getclass(e)) == ELFCLASSNONE) {
        errx(EXIT_FAILURE , "getclass() failed: %s.", elf_errmsg(-1));
    }

    (void) printf("%s: %d-bit ELF object\n", argv[1], version == ELFCLASS32 ? 32 : 64);

    if (elf_getshdrnum(e, &n) != 0)
        errx(EXIT_FAILURE , "getshdrnum() failed: %s.", elf_errmsg(-1));

    if (elf_getshdrstrndx(e, &shstrndx) != 0)
        errx(EXIT_FAILURE , "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));

    scn = NULL;
    int code_seg_idx, data_seg_idx;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            errx(EXIT_FAILURE , "getshdr() failed: %s.", elf_errmsg(-1));
        if ((name = elf_strptr(e, shstrndx , shdr.sh_name)) == NULL)
            errx(EXIT_FAILURE , "elf_strptr() failed: %s.", elf_errmsg(-1));
        (void) printf("Section %-4.4jd %s\n", (uintmax_t) elf_ndxscn(scn), name);

        if (0 == strcmp(name, ".text")) {
            code_seg_idx = (uintmax_t) elf_ndxscn(scn);
        } else if (0 == strcmp(name, ".data")) {
            data_seg_idx = (uintmax_t) elf_ndxscn(scn);
        }
    }



    shstrndx = code_seg_idx;

    if ((scn = elf_getscn(e, shstrndx)) == NULL)
        errx(EXIT_FAILURE , "getscn() failed: %s.", elf_errmsg(-1));

    if (gelf_getshdr(scn, &shdr) != &shdr)
        errx(EXIT_FAILURE , "getshdr(shstrndx) failed: %s.", elf_errmsg(-1));

    (void) printf(".text: size=%jd\n", (uintmax_t) shdr.sh_size);

    data = NULL; n = 0;
    while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
        p = (char *) data ->d_buf;
        while (p < (char *) data->d_buf + data->d_size) {
            // if (vis(pc, *p, VIS_WHITE , 0))
            //     printf("%s", pc);
            n++;
            p++;
            // (void) putchar((n % 16) ? ' ' : '\n');
        }
    }
    (void) putchar('\n');

    printf("%d %d\n", code_seg_idx, data_seg_idx);

    (void) elf_end(e);
    (void) close(fd);
    exit(EXIT_SUCCESS);
}