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

#define PKEY_ID_PKCS7 2

static char magic_number[] = "~Module signature appended~\n";

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

#define ERR(cond, fmt, ...)              \
    do {                                \
        bool __cond = (cond);           \
        display_openssl_errors(__LINE__); \
        if (__cond) {                   \
            err(1, fmt, ## __VA_ARGS__); \
        }                               \
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
    BIO *b = BIO_new_file(private_key_name, "rb");
    ERR(!b, "%s", private_key_name);
    private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb, NULL);
    ERR(!private_key, "%s", private_key_name);
    BIO_free(b);
    return private_key;
}

static X509 *read_x509(const char *x509_name)
{
    X509 *x509;
    BIO *b = BIO_new_file(x509_name, "rb");
    ERR(!b, "%s", x509_name);
    x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
    ERR(!x509, "%s", x509_name);
    BIO_free(b);
    return x509;
}

static void sign_module(const char *module_name, const char *private_key_name, const char *x509_name, const char *hash_algo, const char *dest_name)
{
    EVP_PKEY *private_key = read_private_key(private_key_name);
    X509 *x509 = read_x509(x509_name);

    BIO *bm = BIO_new_file(module_name, "rb");
    ERR(!bm, "%s", module_name);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha1(), NULL);
    unsigned char buf[4096];
    int n;
    while ((n = BIO_read(bm, buf, sizeof(buf))) > 0) {
        EVP_DigestUpdate(md_ctx, buf, n);
    }
    EVP_DigestFinal_ex(md_ctx, buf, NULL);
    EVP_MD_CTX_free(md_ctx);

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(private_key, NULL);
    ERR(!pkey_ctx, "EVP_PKEY_CTX_new");

    if (EVP_PKEY_sign_init(pkey_ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    size_t sig_len = 0;
    if (EVP_PKEY_sign(pkey_ctx, NULL, &sig_len, buf, EVP_MD_size(EVP_sha1())) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    unsigned char *sig = OPENSSL_malloc(sig_len);
    if (!sig) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (EVP_PKEY_sign(pkey_ctx, sig, &sig_len, buf, EVP_MD_size(EVP_sha1())) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    BIO *bd = BIO_new_file(dest_name, "wb");
    ERR(!bd, "%s", dest_name);

    ERR(BIO_write(bd, buf, sig_len) < 0, "%s", dest_name);
    ERR(BIO_write(bd, magic_number, sizeof(magic_number) - 1) < 0, "%s", dest_name);

    ERR(BIO_free(bd) < 0, "%s", dest_name);
}

int main(int argc, char **argv)
{
    char *hash_algo = NULL;
    char *private_key_name = NULL, *x509_name, *module_name, *dest_name;
    bool save_sig = false, replace_orig;
    bool raw_sig = false;
    unsigned char buf[4096];
    unsigned long module_size, sig_size;
    int opt, n;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ERR_clear_error();

    key_pass = getenv("KBUILD_SIGN_PIN");

    do {
        opt = getopt(argc, argv, "sdpk");
        switch (opt) {
        case 's': raw_sig = true; break;
        case 'p': save_sig = true; break;
        case 'd': save_sig = true; break;
        default: format(); break;
        }
    } while (opt != -1);

    argc -= optind;
    argv += optind;
    if (argc < 4 || argc > 5)
        format();

    if (raw_sig) {
        hash_algo = argv[1];
    } else {
        hash_algo = argv[0];
        private_key_name = argv[1];
    }
    x509_name = argv[2];
    module_name = argv[3];
    if (argc == 5) {
        dest_name = argv[4];
        replace_orig = false;
    } else {
        ERR(asprintf(&dest_name, "%s.~signed~", module_name) < 0, "asprintf");
        replace_orig = true;
    }

    if (strcmp(hash_algo, "sha1") != 0) {
        fprintf(stderr, "sign-file: %s only supports SHA1 signing\n", OPENSSL_VERSION_TEXT);
        exit(3);
    }

    sign_module(module_name, private_key_name, x509_name, hash_algo, dest_name);

    if (replace_orig)
        ERR(rename(dest_name, module_name) < 0, "%s", dest_name);

    return 0;
}
