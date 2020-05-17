/**************************************************************************
 * 
 * Copyright © 2020, Jingtang Zhang, Hua Zong.
 * 
 * Some source code is from Linux kernel source (script/sign-file.c)
 * 
 * The origin copyright is as follows. We modified this file originally
 * developed for kernel module signature to implement our ELF signature
 * function.
 * 
 * To compile this file, libssl should be installed. During compilation,
 * add "cc ... -lcrypto" to use the library.
 * 
 * @author Mr Dk.
 * @since 2020/04/20
 * @version 2020/05/17
 * 
 * ***********************************************************************/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>  
#include <fcntl.h>
#include <elf.h>

#define SCN_SYMTAB ".symtab"
#define SCN_STRTAB ".strtab"
#define SCN_SHSTRTAB ".shstrtab"
#define SCN_TEXT ".text"
#define SCN_TEXT_SIG ".text_sig"

char SIG_SUFFIX[] = "_sig";

/* Sign a module file using the given key.
 *
 * Copyright © 2014-2016 Red Hat, Inc. All Rights Reserved.
 * Copyright © 2015      Intel Corporation.
 * Copyright © 2016      Hewlett Packard Enterprise Development LP
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *          Juerg Haefliger <juerg.haefliger@hpe.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

/*
 * Use CMS if we have openssl-1.0.0 or newer available - otherwise we have to
 * assume that it's not available and its header file is missing and that we
 * should use PKCS#7 instead.  Switching to the older PKCS#7 format restricts
 * the options we have on specifying the X.509 certificate we want.
 *
 * Further, older versions of OpenSSL don't support manually adding signers to
 * the PKCS#7 message so have to accept that we get a certificate included in
 * the signature message.  Nor do such older versions of OpenSSL support
 * signing with anything other than SHA1 - so we're stuck with that if such is
 * the case.
 */
#if defined(LIBRESSL_VERSION_NUMBER) || \
	OPENSSL_VERSION_NUMBER < 0x10000000L || \
	defined(OPENSSL_NO_CMS)
#define USE_PKCS7
#endif
#ifndef USE_PKCS7
#include <openssl/cms.h>
#else
#include <openssl/pkcs7.h>
#endif

struct elf_signature {
	uint8_t		algo;		/* Public-key crypto algorithm [0] */
	uint8_t		hash;		/* Digest algorithm [0] */
	uint8_t		id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t		signer_len;	/* Length of signer's name [0] */
	uint8_t		key_id_len;	/* Length of key identifier [0] */
	uint8_t		__pad[3];
	uint32_t	sig_len;	/* Length of signature data */
};

#define PKEY_ID_PKCS7 2

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr,
		"Usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]\n");
	fprintf(stderr,
		"       scripts/sign-file -s <raw sig> <hash algo> <x509> <module> [<dest>]\n");
	exit(2);
}

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

static void drain_openssl_errors(void)
{
	const char *file;
	int line;

	if (ERR_peek_error() == 0)
		return;
	while (ERR_get_error_line(&file, &line)) {}
}

#define ERR(cond, fmt, ...)				\
	do {						\
		bool __cond = (cond);			\
		display_openssl_errors(__LINE__);	\
		if (__cond) {				\
			err(1, fmt, ## __VA_ARGS__);	\
		}					\
	} while(0)

static const char *key_pass;

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	int pwlen;

	if (!key_pass)
		return -1;

	pwlen = strlen(key_pass);
	if (pwlen >= len)
		return -1;

	strcpy(buf, key_pass);

	/* If it's wrong, don't keep trying it. */
	key_pass = NULL;

	return pwlen;
}

static EVP_PKEY *read_private_key(const char *private_key_name)
{
	EVP_PKEY *private_key;

	if (!strncmp(private_key_name, "pkcs11:", 7)) {
		ENGINE *e;

		ENGINE_load_builtin_engines();
		drain_openssl_errors();
		e = ENGINE_by_id("pkcs11");
		ERR(!e, "Load PKCS#11 ENGINE");
		if (ENGINE_init(e))
			drain_openssl_errors();
		else
			ERR(1, "ENGINE_init");
		if (key_pass)
			ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0),
			    "Set PKCS#11 PIN");
		private_key = ENGINE_load_private_key(e, private_key_name,
						      NULL, NULL);
		ERR(!private_key, "%s", private_key_name);
	} else {
		BIO *b;

		b = BIO_new_file(private_key_name, "rb");
		ERR(!b, "%s", private_key_name);
		private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb,
						      NULL);
		ERR(!private_key, "%s", private_key_name);
		BIO_free(b);
	}

	return private_key;
}

static X509 *read_x509(const char *x509_name)
{
	unsigned char buf[2];
	X509 *x509;
	BIO *b;
	int n;

	b = BIO_new_file(x509_name, "rb");
	ERR(!b, "%s", x509_name);

	/* Look at the first two bytes of the file to determine the encoding */
	n = BIO_read(b, buf, 2);
	if (n != 2) {
		if (BIO_should_retry(b)) {
			fprintf(stderr, "%s: Read wanted retry\n", x509_name);
			exit(1);
		}
		if (n >= 0) {
			fprintf(stderr, "%s: Short read\n", x509_name);
			exit(1);
		}
		ERR(1, "%s", x509_name);
	}

	ERR(BIO_reset(b) != 0, "%s", x509_name);

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		/* Assume raw DER encoded X.509 */
		x509 = d2i_X509_bio(b, NULL);
	else
		/* Assume PEM encoded X.509 */
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO_free(b);
	ERR(!x509, "%s", x509_name);

	return x509;
}

/**
 * To sign the buffer and write the signature to the destination file.
 * 
 * @segment_buf: The buffer address to be signed.
 * @segment_len: The length of the buffer.
 * @hash_algo: The name of the hash algorithm for digest.
 * @private_key_name: The private-key file.
 * @x509_name: The X.509 file.
 * @section_name: The name of the section to be signed.
 * 
 * @author Mr Dk.
 * @since 2020/04/24
 * @version 2020/05/05
 */
static void sign_section(void *segment_buf, size_t segment_len,
	char *hash_algo, char *private_key_name, char *x509_name,
	char *section_name)
{
	struct elf_signature sig_info = { .id_type = PKEY_ID_PKCS7 };
	unsigned long sig_size = 0;
	unsigned int use_signed_attrs;
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key;
#ifndef USE_PKCS7
	CMS_ContentInfo *cms = NULL;
	unsigned int use_keyid = 0;
#else
	PKCS7 *pkcs7 = NULL;
#endif
	X509 *x509;
	BIO *bd, *bm;
	int opt, n;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	key_pass = getenv("KBUILD_SIGN_PIN");

#ifndef USE_PKCS7
	use_signed_attrs = CMS_NOATTR;
#else
	use_signed_attrs = PKCS7_NOATTR;
#endif

	/* Read private key. */
	bm = BIO_new_mem_buf(segment_buf, segment_len);
	private_key = read_private_key(private_key_name);
	x509 = read_x509(x509_name);

	/* Digest the module data. */
	OpenSSL_add_all_digests();
	display_openssl_errors(__LINE__);
	digest_algo = EVP_get_digestbyname(hash_algo);
	ERR(!digest_algo, "EVP_get_digestbyname");

#ifndef USE_PKCS7
	/* Load the signature message from the digest buffer. */
	cms = CMS_sign(NULL, NULL, NULL, NULL,
				CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY |
				CMS_DETACHED | CMS_STREAM);
	ERR(!cms, "CMS_sign");

	ERR(!CMS_add1_signer(cms, x509, private_key, digest_algo,
					CMS_NOCERTS | CMS_BINARY |
					CMS_NOSMIMECAP | use_keyid |
					use_signed_attrs),
		"CMS_add1_signer");
	ERR(CMS_final(cms, bm, NULL, CMS_NOCERTS | CMS_BINARY) < 0,
		"CMS_final");

#else
	pkcs7 = PKCS7_sign(x509, private_key, NULL, bm,
				PKCS7_NOCERTS | PKCS7_BINARY |
				PKCS7_DETACHED | use_signed_attrs);
	ERR(!pkcs7, "PKCS7_sign");
#endif

	char new_sec_name[32];
	strcpy(new_sec_name, section_name);
	strcat(new_sec_name, SIG_SUFFIX);

	bd = BIO_new_file(new_sec_name, "wb");
	// bd = BIO_new(BIO_s_mem());
	ERR(!bd, "%s", new_sec_name);
#ifndef USE_PKCS7
	ERR(i2d_CMS_bio_stream(bd, cms, NULL, 0) < 0, "%s", "Fail to sign.");
#else
	ERR(i2d_PKCS7_bio(bd, pkcs7) < 0, "%s", "Fail to sign.");
#endif

	sig_size = BIO_number_written(bd);
	(void) printf(" --- Signature size of [%s]: %ld\n", section_name, sig_size);

	// sig_info.sig_len = htonl(sig_size);
	// ERR(BIO_write(bd, &sig_info, sizeof(sig_info)) < 0, "%s",
	// 	"Fail to write signature info.");

	// BUF_MEM *bptr;
	// BIO_get_mem_ptr(bd, &bptr);
	// BIO_set_close(bd, BIO_NOCLOSE);

	ERR(BIO_free(bd) < 0, "Fail to free signature buffer");

	(void) printf(" --- Writing signature to file: %s\n", new_sec_name);
}

/**
 * File operation wrapper for convenient signature injection.
 * 
 * @author Mr Dk.
 * @since 2020/05/17
 */
#define FILE_READ 0
#define FILE_WRITE 1
#define FILE_INJECT 2
#define FILE_WIPE 3

/**
 * Read or write bytes at specific offset in file.
 * ATTENTION: write operation will directly OVERRIDE original bytes.
 * 
 * @fd: The file descriptor of the file.
 * @off: The offset to the BEGINNING of the file.
 * @buf: The buffer space for reading or writing.
 * @len: The size in bytes to read or write.
 * @flag: Only FILE_READ or FILE_WRITE in valid.
 */
static size_t file_rw(int fd, long off, void *buf, size_t len, int flag)
{
	size_t n = lseek(fd, off, SEEK_SET);
	ERR(n < 0, "Failed to seek section header.");

	return flag == FILE_WRITE ? write(fd, buf, len) :
			(flag == FILE_READ ? read(fd, buf, len) : -1);
}

/**
 * Inject or wipe bytes at specific offset in file.
 * ATTENTION: these operation will affect the length of the file.
 * 
 * @file_name: The file name to be modified.
 * @pos: The position in file to start modification.
 * @content: The content buffer to be injected (Not used by wipping).
 * @len: The size in bytes to inject or wipe.
 * @flag: Only FILE_INJECT or FILE_WIPE in valid.
 */
static size_t file_modify(char *file_name, size_t pos,
		char *content, size_t len, int flag)
{
	char tmp_file_name[256];
	strcpy(tmp_file_name, file_name);
	strcat(tmp_file_name, ".tmp");

	int fd_tmp = open(tmp_file_name, O_WRONLY | O_CREAT, 0777);
	int fd_origin = open(file_name, O_RDONLY);

	size_t off = 0;
	size_t n = 0;
	char buffer[512];

	/**
	 * Copy until reaching specified position.
	 */
	while (off < pos) {
		if ((pos - off) <= sizeof(buffer)) {
			/* Less than a buffer. */
			n = read(fd_origin, buffer, pos - off);
		} else {
			n = read(fd_origin, buffer, sizeof(buffer));
		}
		ERR(n < 0, "Failed to read original ELF.");
		off += n;
		n = write(fd_tmp, buffer, n);
		ERR(n < 0, "Failed to write tmp ELF.");
	}

	if (flag == FILE_INJECT) {
		/* Inject the additional content. */
		n = write(fd_tmp, content, len);
		ERR(n < 0, "Failed to inject tmp ELF.");
		off += len;
	} else if (flag == FILE_WIPE) {
		/* Ignore len bytes in original file. */
		n = lseek(fd_origin, len, SEEK_CUR);
		ERR(n < 0, "Failed to ignore original ELF.");
	}

	/**
	 * Copy the rest.
	 */
	while ((n = read(fd_origin, buffer, sizeof(buffer)))) {
		ERR(n < 0, "Failed to read original ELF.");
		off += n;
		n = write(fd_tmp, buffer, n);
		ERR(n < 0, "Failed to write tmp ELF.");
	}

	close(fd_origin);
	close(fd_tmp);

	/**
	 * Remove the original file, rename the temporary file
	 * to the original file.
	 */
	ERR(remove(file_name) < 0, "Failed to remove original file.");
	ERR(rename(tmp_file_name, file_name) < 0,
			"Failed to rename original file.");

	return off;
}

/**
 * Add a specific section to the specific ELF file.
 * The signature has already on the file system, e.g., .text_sig.
 * 
 * @file_name: The ELF file that will be appended a section.
 * @section_name: The name of the section being signed.
 */
static void insert_new_section(char *file_name, char *section_name)
{
	size_t n = 0;
	int fd = -1;

	/**
	 * Prepared for the signature in memory.
	 */
	struct stat statbuff;
	ERR(stat(section_name, &statbuff) < 0, "Failed to read signature length.");
	size_t sig_len = statbuff.st_size;

	char *sig_buf = (char *) malloc(sig_len);
	ERR(!sig_buf, "Failed to malloc for signature data.");

	fd = open(section_name, O_RDONLY);
	ERR(fd < 0, "Failed to open file.");
	sig_len = read(fd, sig_buf, sig_len);
	close(fd);

	/**
	 * Start to parse the ELF file.
	 * At first, load ELF Header into memory.
	 */
	fd = open(file_name, O_RDWR);
	ERR(fd < 0, "Failed to open file.");
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
	ERR(!ehdr, "Failed to malloc ELF header.");
	n = file_rw(fd, 0, ehdr, sizeof(Elf64_Ehdr), FILE_READ);
	ERR(n < 0, "Failed to read ELF header.");

	/**
	 * Load section header table into memory. Especially, allocate
	 * ONE MORE ROOM for the new section header table entry.
	 */
	Elf64_Shdr *shdr = (Elf64_Shdr *)
			malloc(ehdr->e_shentsize * (ehdr->e_shnum + 1));
	ERR(!shdr, "Failed to malloc for section header table.");
	n = file_rw(fd, ehdr->e_shoff, shdr,
			ehdr->e_shentsize * ehdr->e_shnum, FILE_READ);
	ERR(n < 0, "Failed to read section header.");

	/**
	 * Load data of ".shstrtab" section to get all sections' name.
	 */
	Elf64_Shdr *shdr_strtab = shdr + ehdr->e_shstrndx;
	char *strtab = (char *) malloc(shdr_strtab->sh_size);
	ERR(!strtab, "Failed to malloc for section header string table.");
	n = file_rw(fd, shdr_strtab->sh_offset, strtab, shdr_strtab->sh_size, FILE_READ);
	ERR(n < 0, "Failed to read section header string table.");

	/**
	 * Calculate the injected size of signature section data.
	 * The injected size is aligned at 8-bytes to make the following
	 * section to start at 8-bytes alignment.
	 * 
	 * e.g. for a signature section with 11 bytes data:
	 * 
	 * Signature section:
	 * 0x0000 xx xx xx xx xx xx xx xx
	 * 0x0008 xx xx xx 00 00 00 00 00
	 * Next section (start at 8-bytes alignment):
	 * 0x0010 ......
	 */
	long inject_sig_len = sig_len;
	if (sig_len % 8) {
		inject_sig_len += (8 - sig_len % 8);
	}

	/**
	 * Calculate the injected size into the string table section,
	 * for the section name of the new section.
	 * 
	 * Calculate the offset in file to inject, and calculate the
	 * character offset in string table for the name index field
	 * of the new section header entry.
	 * 
	 * Originally, the section header is aligned at 8-bytes. So
	 * there are some paddings at the end of ".shstrtab". We firstly
	 * override these bytes with the name of new section. If it is
	 * not enough, we inject the rest characters of the section name,
	 * and also make the data of ".shstrtab" to be aligned at 8-bytes,
	 * so that the section header table will start at 8-bytes alignment.
	 * 
	 * Update the length of ".shstrtab" section in memory.
	 */
	long inject_strtab = strlen(section_name) + 1;
	long scn_name_off = shdr_strtab->sh_offset + shdr_strtab->sh_size;
	long in_strtab_off = shdr_strtab->sh_size;
	shdr_strtab->sh_size += inject_strtab;

	long padding_override = 8 - scn_name_off % 8; /* Use existing paddings. */
	n = file_rw(fd, scn_name_off, section_name, padding_override, FILE_WRITE);
	ERR(n < 0, "Failed to override string table.");
	inject_strtab -= padding_override; /* Rest to be injected. */

	if (inject_strtab > 0 && inject_strtab % 8) {
		inject_strtab += (8 - inject_strtab % 8); /* Padding to 8-bytes. */
	}

	/**
	 * Move the last THREE section (.symtab .strtab .shstrtab) backward.
	 * Use the one addtional room allocated before.
	 * 
	 * During memcpy, update the section data's offset in file (Adding 
	 * the length of the signature data), and also update the
	 * linking info of sections.
	 */
	Elf64_Shdr *shdr_p = shdr + ehdr->e_shnum;
	for (; shdr_p > shdr + ehdr->e_shnum - 3; shdr_p--) {
		memcpy(shdr_p, shdr_p - 1, sizeof(Elf64_Shdr));

		/* Last three section must be three of them. */
		if (memcmp(strtab + shdr_p->sh_name, SCN_SYMTAB, sizeof(SCN_SYMTAB)) &&
			memcmp(strtab + shdr_p->sh_name, SCN_STRTAB, sizeof(STRTAB)) &&
			memcmp(strtab + shdr_p->sh_name, SCN_SHSTRTAB, sizeof(SCN_SHSTRTAB))) {
			ERR(1, "Invalid layout of ELF.");
		}
		
		shdr_p->sh_offset += inject_sig_len;
		if (shdr_p->sh_link) {
			shdr_p->sh_link += 1;
		}
	}

	/**
	 * Fill in the new section header entry in memory, and override
	 * the whole section header table in the file.
	 */
	Elf64_Shdr *new_shdr = shdr + ehdr->e_shnum - 3;
	new_shdr->sh_name = in_strtab_off;
	new_shdr->sh_size = sig_len;
	new_shdr->sh_addr = 0;
	new_shdr->sh_addralign = 1;
	new_shdr->sh_flags = SHF_OS_NONCONFORMING;
	new_shdr->sh_type = SHT_PROGBITS;
	new_shdr->sh_info = 0;
	new_shdr->sh_link = 0;

	n = file_rw(fd, ehdr->e_shoff, shdr,
			sizeof(Elf64_Shdr) * (ehdr->e_shnum + 1), FILE_WRITE);
	ERR(n < 0, "%s", "Failed to override section header table.");

	/**
	 * Update the ELF header about the info of section header table, and
	 * override the ELF header in file.
	 * The increased offset of the section header table include two parts:
	 *     1. the new section's data
	 *     2. the new section's name in string table section
	 */
	ehdr->e_shstrndx += 1;
	ehdr->e_shnum += 1;
	ehdr->e_shoff += inject_sig_len;
	if (inject_strtab > 0) {
		ehdr->e_shoff += inject_strtab;
	}

	n = file_rw(fd, 0, ehdr, sizeof(Elf64_Ehdr), FILE_WRITE);
	ERR(n < 0, "%s", "Failed to override ELF header.");

	/**
	 * Now the override of the file completes. Before starting to
	 * inject the real raw data, close the file descriptor.
	 * 
	 * Inject the section's name string first, or the offset may be
	 * influenced by the second call of file_modify().
	 */
	close(fd);
	if (inject_strtab > 0) {
		file_modify(file_name, scn_name_off + padding_override,
			section_name + padding_override, inject_strtab, FILE_INJECT);
	}
	file_modify(file_name, new_shdr->sh_offset,
			sig_buf, inject_sig_len, FILE_INJECT);

	// int i = 0;
	// for (Elf64_Shdr *shdr_p = shdr; i < ehdr->e_shnum; shdr_p++, i++) {
	// 	printf("%02d %04ld %04ld %03d\n", i, shdr_p->sh_offset, shdr_p->sh_size, shdr_p->sh_name);
	// }

	/**
	 * Injection is successful, clean up the signature data file.
	 * Clean up the memory.
	 */
	ERR(remove(section_name) < 0, "Failed to remove %s", section_name);
	printf(" --- Removing temp signature file: %s\n", section_name);

	free(sig_buf);
	free(strtab);
	free(shdr);
	free(ehdr);
	sig_buf = NULL;
	ehdr = NULL;
	shdr = NULL;
	strtab = NULL;
}

/**
 * Make a copy of unsigned ELF file for back up.
 * 
 * @elf_name: The ELF file name to be copied.
 */
static void elf_back_up(char *elf_name) {

	char backup_name[256];
	strcpy(backup_name, elf_name);
	strcat(backup_name, ".old");

	int fd_backup = open(backup_name, O_WRONLY | O_CREAT, 0777);
	ERR(fd_backup < 0, "%s", "Failed to open back up file.");
	int fd_origin = open(elf_name, O_RDONLY);
	ERR(fd_origin < 0, "%s", "Failed to open origin file.");

	size_t len = 0;
	while (len = read(fd_origin, backup_name, sizeof(backup_name))) {
		write(fd_backup, backup_name, len);
	}

	close(fd_backup);
	close(fd_origin);
}

/**
 * 
 * The program entry point.
 * 
 * @argv[1]: The ELF file to be signed.
 * @argv[2]: The hash algorithm for making digest.
 * @argv[3]: The file containing private key.
 * @argv[4]: The file containing X.509.
 * @argv[5]: The destination file for storing signature.
 * 
 * @author Mr Dk.
 * @since 2020/04/20
 * @version 2020/05/17
 * 
 */
int main(int argc, char **argv) {

	char *elf_name = argv[1];
	char *hash_algo = argv[2];
	char *private_key_name = argv[3];
	char *x509_name = argv[4];
	char *dest_name = argv[5];

	int fd = -1;
	size_t n = 0;

	/**
	 * Open the file, and do necessary ELF format recognition with
	 * in-memory ELF header.
	 */
	fd = open(elf_name, O_RDONLY);
	ERR(fd < 0, "%s", "Failed to open file.");
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
	ERR(!ehdr, "%s", "Failed to malloc ELF header.");
	n = file_rw(fd, 0, ehdr, sizeof(Elf64_Ehdr), FILE_READ);
	ERR(n < 0, "%s", "Failed to read ELF header.");

	ERR(memcmp(ehdr->e_ident, ELFMAG, SELFMAG), "%s", "Invalid ELF file.");
	ERR(ehdr->e_ident[EI_VERSION] != EV_CURRENT, "%s", "Not support ELF version.");
	ERR(ehdr->e_ident[EI_CLASS] != ELFCLASS64, "%s", "Not support byte long.");
	printf(" --- 64-bit ELF file, version 1 (CURRENT).\n");

	switch (ehdr->e_ident[EI_DATA]) {
		case ELFDATA2MSB:
			printf(" --- Big endian.\n");
			break;
		case ELFDATA2LSB:
			printf(" --- Little endian.\n");
			break;
		default:
			ERR(1, "%s", "Not support data encoding.");
			break;
	}

	printf(" --- %d sections detected.\n", ehdr->e_shnum);

	/**
	 * Prepared for section header table and string table section.
	 */
	Elf64_Shdr *shdr = (Elf64_Shdr *)
			malloc(ehdr->e_shentsize * (ehdr->e_shnum));
	ERR(!shdr, "%s", "Failed to malloc ELF section header table.");
	n = file_rw(fd, ehdr->e_shoff, shdr,
			ehdr->e_shentsize * ehdr->e_shnum, FILE_READ);
	ERR(n < 0, "%s", "Failed to read section header.");

	Elf64_Shdr *shdr_strtab = shdr + ehdr->e_shstrndx;
	char *strtab = (char *) malloc(shdr_strtab->sh_size);
	ERR(!strtab, "%s", "Failed to malloc string table.");
	n = file_rw(fd, shdr_strtab->sh_offset, strtab,
			shdr_strtab->sh_size, FILE_READ);
	ERR(n < 0, "%s", "Failed to read string table.");

	/**
	 * Iterate over sections to find the section being signed.
	 * If a signature section is detected, throw an error.
	 */
	int i = 0;
	for (Elf64_Shdr *shdr_p = shdr; i < ehdr->e_shnum; shdr_p++, i++) {
		char *scn_name = strtab + shdr_p->sh_name;
		if (!memcmp(scn_name, SCN_TEXT, 5)) {
			printf(" --- Section %-4.4d [%s] detected.\n", i, scn_name);
			printf(" --- Length of section [%s]: %ld\n",
					scn_name, shdr_p->sh_size);

			char *scn_data = (char *) malloc(shdr_p->sh_size);
			ERR(!scn_data, "%s", "Failed to malloc for section data.");
			file_rw(fd, shdr_p->sh_offset, scn_data,
					shdr_p->sh_size, FILE_READ);

			sign_section(scn_data, shdr_p->sh_size,
					hash_algo, private_key_name, x509_name, scn_name);

			free(scn_data);
			scn_data = NULL;

		} else if (!memcmp(scn_name, SCN_TEXT_SIG, 9)) {
			ERR(1, "%s", "File already been signed!");
		}
	}

	close(fd);
	free(strtab);
	free(shdr);
	free(ehdr);
	ehdr = NULL;
	shdr = NULL;
	strtab = NULL;

	/**
	 * Make a copy of unsigned file.
	 */
	elf_back_up(elf_name);

	/**
	 * Add signature section into target ELF.
	 */
	insert_new_section(elf_name, SCN_TEXT_SIG);

	return 0;
}