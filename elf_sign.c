/**************************************************************************
 * 
 * Copyright © 2020, Jingtang Zhang, Hua Zong.
 * 
 * Some source code is from Linux kernel source (script/sign-file.c)
 * 
 * The origin copyright is as follows. We modified the file for developed
 * for kernel module signature to our ELF signature function.
 * 
 * To compile this file, libssl and libelf should be installed. During
 * compilation, add "cc ... -lelf -lcrypto" to use these libraries.
 * 
 * Also, the program needs other programs including mv and objcopy.
 * 
 * @author Mr Dk.
 * @since 2020/04/20
 * @version 2020/04/25
 * 
 * ***********************************************************************/

#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/wait.h>

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
	char *section_name) {

	struct elf_signature sig_info = { .id_type = PKEY_ID_PKCS7 };
	unsigned long sig_size;
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

	// sig_size = BIO_number_written(bd);
	// sig_info.sig_len = htonl(sig_size);
	// ERR(BIO_write(bd, &sig_info, sizeof(sig_info)) < 0, "%s",
	// 	"Fail to write signature info.");

	// BUF_MEM *bptr;
	// BIO_get_mem_ptr(bd, &bptr);
	// BIO_set_close(bd, BIO_NOCLOSE);

	ERR(BIO_free(bd) < 0, "%s", "Fail to free signature buffer");

	(void) printf("Writing signature to: %s\n", new_sec_name);
}

/**
 * Add a specific section to the specific ELF file.
 * The signature has already on the file system, e.g., .text_sig.
 * 
 * e.g. objcopy \
 *          --add-section .text_sig=.text_sig \
 *          --set-section-flags .text_sig=readonly \
 *          <elf-file>
 * 
 * @file_name: The ELF file that will be appended a section.
 * @section_name: The name of the section being signed.
 */
static void add_signature_section(char *file_name, char *section_name) {

	char sig_file_name[32];
	strcpy(sig_file_name, section_name);
	strcat(sig_file_name, SIG_SUFFIX);

	char new_section_name[64];
	strcpy(new_section_name, sig_file_name);
	strcat(new_section_name, "=");
	strcat(new_section_name, sig_file_name);

	char section_flags[64];
	strcpy(section_flags, sig_file_name);
	strcat(section_flags, "=readonly");

	/**
	 * Prepare for the arguments.
	 */
	char *argv[] = {
		"objcopy",
		"--add-section", new_section_name,
		"--set-section-flags", section_flags,
		file_name, NULL
	};

	/**
	 * Fork a new process to invoke objcopy.
	 */
	int pid = fork();
	if (pid == 0) {
		ERR(execvp("objcopy", argv) < 0, "%s", "Failed to use objcopy.");
		exit(0);
	}
	waitpid(pid, NULL, 0);

	/**
	 * Remove the signature file.
	 */
	remove(sig_file_name);
	(void) printf("Removing %s\n", sig_file_name);
}

/**
 * Remove the existing signature section to the specific ELF file,
 * whose suffix of the section name is "_sig", e.g., .text_sig.
 * 
 * e.g. objcopy \
 *          --remove-section .text_sig \
 *          <elf-file>
 * 
 * @file_name: The ELF file whose signature section will be removed.
 * @section_name: The name of the section to be removed.
 */
static void remove_signature_section(char *file_name, char *section_name) {
	/**
	 * Prepare for the arguments.
	 */
	char *argv[] = {
		"objcopy",
		"--remove-section", section_name,
		file_name, NULL
	};

	/**
	 * Fork a new process to invoke objcopy.
	 */
	int pid = fork();
	if (pid == 0) {
		ERR(execvp("objcopy", argv) < 0, "%s", "Failed to use objcopy.");
		exit(0);
	}
	waitpid(pid, NULL, 0);

	(void) printf("Removing original signature section: %s\n", section_name);
}

/**
 * Make a copy of unsigned ELF file for back-up.
 * 
 * @elf_file_name: The ELF file name to be copied.
 */
static void elf_back_up(char *elf_file_name) {

	char backup_file_name[256];
	strcpy(backup_file_name, elf_file_name);
	strcat(backup_file_name, ".old");

	char *argv[] = {
		"cp",
		elf_file_name, backup_file_name,
		NULL
	};

	int pid = fork();
	if (pid == 0) {
		ERR(execvp("cp", argv) < 0, "%s", "Failed to use cp.");
		exit(0);
	}
	waitpid(pid, NULL, 0);
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
 * @version 2020/04/25
 * 
 */
int main(int argc, char **argv) {

	char *elf_name = argv[1];
	char *hash_algo = argv[2];
	char *private_key_name = argv[3];
	char *x509_name = argv[4];
	char *dest_name = argv[5];

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
	(void) printf("%s: %d-bit ELF object\n", elf_name, version == ELFCLASS32 ? 32 : 64);

	size_t sh_count = 0;
	if (elf_getshdrnum(elf, &sh_count) != 0) {
		errx(EXIT_FAILURE, "getshdrnum() failed: %s.", elf_errmsg(-1));
	}
	(void) printf("%ld sections detected.\n", sh_count);

	size_t shstrndx = 0;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	}
	// (void) printf("%ld section index\n", shstrndx);

	Elf_Data *data = NULL;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	unsigned char *section_name, *p;

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
		if (0 == strcmp(section_name, ".text")) {
			
			(void) printf("Section %-4.4jd %s\n",
				(uintmax_t) elf_ndxscn(scn), section_name);
			(void) printf("Length of section %s: %ld\n", section_name, shdr.sh_size);

			if ((data = elf_getdata(scn, data)) == NULL) {
				errx(EXIT_FAILURE, "elf_getdata() failed: %s.", elf_errmsg(-1));
			}
			
			printf("Buffer size: %ld\n", data->d_size);
			sign_section(data->d_buf, data->d_size,
				hash_algo, private_key_name, x509_name, section_name);

			// n = 0;
			// int count = 0;
			// printf("Buffer size: %ld\n", data->d_size);
			// while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
			// 	p = (unsigned char *) data->d_buf;
			// char buf[1024*1024*7];
			// 	printf("Buffer size: %ld\n", data->d_size);
			// 	while (p < (unsigned char *) data->d_buf + data->d_size) {
			// 		// printf("%02x", *p);
			// 		buf[count] = *p;
			// 		count++;
			// 		n++;
			// 		p++;
			// 		// (void) putchar((n % 16) ? ' ' : '\n');
			// 		if (count > sizeof(buf)) {
			// 			break;
			// 		}
			// 	}
			// 	if (count > sizeof(buf)) {
			// 		break;
			// 	}
			// }

			// sign_section(buf, count, hash_algo, private_key_name, x509_name, dest_name);

		} else if (strlen(section_name) > 4 &&
					0 == strncmp(
						section_name + strlen(section_name) - (sizeof(SIG_SUFFIX) - 1),
						SIG_SUFFIX,
						sizeof(SIG_SUFFIX) - 1)) {
			remove_signature_section(elf_name, section_name);
		}
	}

	(void) elf_end(elf);
	(void) close(fd);

	/**
	 * Make a copy of unsigned file.
	 */
	elf_back_up(elf_name);

	/**
	 * Add signature section into target ELF.
	 */
	add_signature_section(elf_name, ".text");

	exit(EXIT_SUCCESS);
}