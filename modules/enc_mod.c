#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "module_api.h"

static const char MAGIC[] = "AESENC01";
static const int SALT_LEN = 16;
static const int IV_LEN = 16;
static const int KEY_LEN = 32;

const char *module_name(void) { return "encrypt"; }
int module_init(void) { OpenSSL_add_all_algorithms(); return 0; }
void module_free(void) { EVP_cleanup(); }

static void derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, SALT_LEN, 10000, EVP_sha256(), KEY_LEN, key);
}

int module_process(const unsigned char *in, size_t inlen,
                   unsigned char **out, size_t *outlen) {
    const char *pass = getenv("CRYPT_PASS");
    unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv, IV_LEN);
    if (pass) {
        derive_key(pass, salt, key);
    } else {
        fprintf(stderr, "[encrypt] WARNING: using demo key (insecure)\n");
        memset(key, 0x42, KEY_LEN);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    unsigned char *ciphertext = malloc(inlen + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, in, inlen)) return -1;
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    *outlen = strlen(MAGIC) + SALT_LEN + IV_LEN + ciphertext_len;
    *out = malloc(*outlen);
    unsigned char *p = *out;
    memcpy(p, MAGIC, strlen(MAGIC)); p += strlen(MAGIC);
    memcpy(p, salt, SALT_LEN); p += SALT_LEN;
    memcpy(p, iv, IV_LEN); p += IV_LEN;
    memcpy(p, ciphertext, ciphertext_len);
    free(ciphertext);
    return 0;
}
