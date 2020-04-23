/**************************************************************************
 * 
 * Copyright (c) 2020, Jingtang Zhang, Hua Zong.
 * 
 * Some source code is from Linux kernel source (script/sign-file.c)
 * 
 * The origin copyright is as follows. We modified the file for developed
 * for kernel module signature to our ELF signature function.
 * 
 * To compile this file, libssl and libelf should be installed. During
 * compilation, add "cc ... -lelf -lcrypto" to use these libraries.
 * 
 * @author mrdrivingduck@gmail.com
 * @since 2020/04/20
 * @version 2020/04/24
 * 
 * ***********************************************************************/

#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

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
 * @param segment_buf The buffer address to be signed.
 * @param segment_len The length of the buffer.
 * @param hash_algo The name of the hash algorithm for digest.
 * @param private_key_name The private-key file.
 * @param x509_name The X.509 file.
 * @param dest_name The destination file for storing signature.
 * 
 * @author Mr Dk.
 * @since 2020/04/24
 */
static void sign_segment(void *segment_buf, size_t segment_len,
							char *hash_algo, char *private_key_name,
							char *x509_name, char *dest_name) {
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
	bd = BIO_new_file(dest_name, "wb");
	// bd = BIO_new(BIO_s_mem());
	ERR(!bd, "%s", dest_name);
#ifndef USE_PKCS7
	ERR(i2d_CMS_bio_stream(bd, cms, NULL, 0) < 0, "%s", "Fail to sign.");
#else
	ERR(i2d_PKCS7_bio(bd, pkcs7) < 0, "%s", "Fail to sign.");
#endif
	sig_size = BIO_number_written(bd);
	sig_info.sig_len = htonl(sig_size);
	ERR(BIO_write(bd, &sig_info, sizeof(sig_info)) < 0, "%s", "Fail to write signature info.");

	// BUF_MEM *bptr;
	// BIO_get_mem_ptr(bd, &bptr);
	// BIO_set_close(bd, BIO_NOCLOSE);

	ERR(BIO_free(bd) < 0, "%s", "Fail to free signature buffer");
}

/**
 * 
 * The program entry point.
 * 
 * @argv[1] - The ELF file to be signed.
 * @argv[2] - The hash algorithm for making digest.
 * @argv[3] - The file containing private key.
 * @argv[4] - The file containing X.509.
 * @argv[5] - The destination file for storing signature.
 * 
 * @author Mr Dk.
 * @since 2020/04/20
 * @version 2020/04/24
 * 
 */
int main(int argc , char **argv) {
	int fd;
	int version;
	Elf *elf;

	Elf_Kind ek;
	GElf_Ehdr eher;
	GElf_Shdr shdr;
	unsigned char *name, *p;

	char buf[1024*1024*7];
	
	size_t n, shstrndx;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE , "ELF library initialization " "failed: %s", elf_errmsg(-1));
	}

	if ((fd = open(argv[1], O_RDONLY , 0)) < 0) {
		err(EXIT_FAILURE , "open \%s\" failed", argv[1]);
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		errx(EXIT_FAILURE , "elf_begin() failed: %s.", elf_errmsg(-1));
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		errx(EXIT_FAILURE, "\"%s\" is not an ELF object.", argv[1]);
	}

	if ((version = gelf_getclass(elf)) == ELFCLASSNONE) {
		errx(EXIT_FAILURE , "getclass() failed: %s.", elf_errmsg(-1));
	}

	(void) printf("%s: %d-bit ELF object\n", argv[1], version == ELFCLASS32 ? 32 : 64);

	if (elf_getshdrnum(elf, &n) != 0)
		errx(EXIT_FAILURE , "getshdrnum() failed: %s.", elf_errmsg(-1));
	printf("%ld sections\n", n);

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		errx(EXIT_FAILURE , "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
	// printf("%ld section index\n", shstrndx);

	char *hash_algo = argv[2];
	char *private_key_name = argv[3];
	char *x509_name = argv[4];
	char *dest_name = argv[5];

	Elf_Data *data;
	Elf_Scn *scn = NULL;
	
	/**
	 * Iterate over sections.
	 */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		/**
		 * Get section header from section header table.
		 * Get section name from section header name table.
		 */
		if (gelf_getshdr(scn, &shdr) != &shdr)
			errx(EXIT_FAILURE , "getshdr() failed: %s.", elf_errmsg(-1));
		if ((name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL)
			errx(EXIT_FAILURE , "elf_strptr() failed: %s.", elf_errmsg(-1));
		(void) printf("Section %-4.4jd %s\n", (uintmax_t) elf_ndxscn(scn), name);

		/**
		 * Code segment.
		 */
		if (0 == strcmp(name, ".text")) {
			n = 0;
			printf("Code segment length: %ld\n", shdr.sh_size);

			if ((data = elf_getdata(scn, data)) != NULL) {
				printf("Buffer size: %ld\n", data->d_size);
				sign_segment(data->d_buf, data->d_size, hash_algo, private_key_name, x509_name, dest_name);
			}

			// int count = 0;
			// printf("Buffer size: %ld\n", data->d_size);
			// while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
			// 	p = (unsigned char *) data->d_buf;
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

			// sign_segment(buf, count, hash_algo, private_key_name, x509_name, dest_name);
		}
	}

	(void) elf_end(elf);
	(void) close(fd);
	exit(EXIT_SUCCESS);
}