#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>

int main() {

    char elf_name[] = "sign-target";

    if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "ELF library initialization " "failed: %s", elf_errmsg(-1));
	}

	int fd = -1;
	if ((fd = open(elf_name, O_RDWR, 0)) < 0) {
		err(EXIT_FAILURE, "open \"%s\" failed", elf_name);
	}

	Elf *elf = NULL;
	if ((elf = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL) {
		errx(EXIT_FAILURE, "elf_begin() failed: %s.", elf_errmsg(-1));
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		errx(EXIT_FAILURE, "\"%s\" is not an ELF object.", elf_name);
	}

	int version = 0;
	if ((version = gelf_getclass(elf)) == ELFCLASSNONE) {
		errx(EXIT_FAILURE, "getclass() failed: %s.", elf_errmsg(-1));
	}
	(void) printf("--- [%s]: %d-bit ELF object\n", elf_name, version == ELFCLASS32 ? 32 : 64);

	size_t sh_count = 0;
	if (elf_getshdrnum(elf, &sh_count) != 0) {
		errx(EXIT_FAILURE, "getshdrnum() failed: %s.", elf_errmsg(-1));
	}
	(void) printf("--- %ld sections detected.\n", sh_count);

	size_t shstrndx = 0;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	}
	// (void) printf("%ld section index\n", shstrndx);

	Elf_Data *data = NULL;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	unsigned char *section_name, *p;

    char content[] = "HAHAHAHA";
    int str_tab_off = 0;

	/**
	 * Iterate over sections.
	 */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		/**
		 * Get section header from section header table.
		 * Get section name from section header name table.
		 */
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1));
		}
		if ((section_name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL) {
			errx(EXIT_FAILURE, "elf_strptr() failed: %s.", elf_errmsg(-1));
		}

		/**
		 * Sign a section
		 */
		if (0 == strcmp(section_name, ".shstrtab")) {
			char str_buf[2048];

			if ((data = elf_getdata(scn, data)) == NULL) {
				errx(EXIT_FAILURE, "elf_getdata() failed: %s.", elf_errmsg(-1));
			}

            str_tab_off = data->d_size;

            memcpy(str_buf, data->d_buf, data->d_size);
            memcpy(str_buf + data->d_size, content, sizeof(content));

            data->d_size += sizeof(content);
            data->d_buf = str_buf;

            if (elf_update(elf, ELF_C_NULL) < 0) {
                errx(EXIT_FAILURE, "elf_update() failed: %s.", elf_errmsg(-1));
            }
            data = NULL;
            // if (elf_update(elf, ELF_C_WRITE) < 0) {
            //     errx(EXIT_FAILURE, "elf_update() failed: %s.", elf_errmsg(-1));
            // }
		}
	}

    if ((scn = elf_newscn(elf)) == NULL) {
        errx(EXIT_FAILURE, "elf_newscn() failed: %s.", elf_errmsg(-1));
    }

    if ((data = elf_newdata(scn)) == NULL) {
        errx(EXIT_FAILURE, "elf_newdata failed: %s.", elf_errmsg(-1));
    }

    data->d_align = 1;
    data->d_off = 0LL;
    data->d_buf = content;
    data->d_type = ELF_T_WORD;
    data->d_size = sizeof(content) - 1;
    data->d_version = EV_CURRENT;


    Elf64_Shdr *shdr_p = NULL;

    if ((shdr_p = elf64_getshdr(scn)) == NULL) {
        errx(EXIT_FAILURE, "elf64_getshdr() failed: %s.", elf_errmsg(-1));
    }
    shdr_p->sh_name = str_tab_off;
    shdr_p->sh_type = SHT_PROGBITS;
    shdr_p->sh_flags = SHF_ALLOC;
    shdr_p->sh_entsize = 0;

    // if (gelf_getshdr(scn, &shdr) != &shdr) {
    //     errx(EXIT_FAILURE, "gelf_getshdr failed: %s.", elf_errmsg(-1));
    // }
    // printf("%d\n", str_tab_off);
    // shdr.sh_name = str_tab_off;
    // shdr.sh_type = SHT_PROGBITS;
    // shdr.sh_flags = SHF_ALLOC;
    // shdr.sh_entsize = 0;

    if (elf_update(elf, ELF_C_NULL) < 0) {
        errx(EXIT_FAILURE, "elf_update() failed: %s.", elf_errmsg(-1));
    }
    if (elf_update(elf, ELF_C_WRITE) < 0) {
        errx(EXIT_FAILURE, "elf_update() failed: %s.", elf_errmsg(-1));
    }

	(void) elf_end(elf);
	(void) close(fd);


    return 0;
}