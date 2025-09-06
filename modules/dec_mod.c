#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "module_api.h"

static const char MAGIC[] = "AESENC01";
static const int SALT_LEN = 16;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;

const char *module_name(void) { return "decrypt"; }
int module_init(void) { OpenSSL_add_all_algorithms(); return 0; }
void module_free(void) { EVP_cleanup(); }

static void derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, SALT_LEN, 10000, EVP_sha256(), KEY_LEN, key);
}

int module_process(const unsigned char *in, size_t inlen,
                   unsigned char **out, size_t *outlen) {
    size_t magic_len = strlen(MAGIC);
    if (inlen < magic_len + SALT_LEN + IV_LEN) return -1;
    if (memcmp(in, MAGIC, magic_len) != 0) {
        fprintf(stderr, "[decrypt] bad magic header\n");
        return -1;
    }

    const unsigned char *p = in + magic_len;
    const unsigned char *salt = p; p += SALT_LEN;
    const unsigned char *iv = p; p += IV_LEN;
    const unsigned char *ciphertext = p;
    size_t ciphertext_len = inlen - magic_len - SALT_LEN - IV_LEN;

    const char *pass = getenv("CRYPT_PASS");
    unsigned char key[KEY_LEN];
    if (pass) {
        derive_key(pass, salt, key);
    } else {
        fprintf(stderr, "[decrypt] WARNING: using demo key (insecure)\n");
        memset(key, 0x42, KEY_LEN);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    unsigned char *plaintext = malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    if (!plaintext) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    *outlen = plaintext_len;
    *out = malloc(*outlen);
    memcpy(*out, plaintext, plaintext_len);
    free(plaintext);
    return 0;
}
