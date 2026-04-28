#ifndef LUKS_UNLOCK_KEYFILE_H
#define LUKS_UNLOCK_KEYFILE_H

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

/* Long-term identity = Ed25519 keypair. We persist the 64-byte secret key;
 * the 32-byte pubkey is recovered from it on load. */

int keyfile_generate(uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                     uint8_t sk[crypto_sign_SECRETKEYBYTES]);

int keyfile_save(const char *path,
                 const uint8_t sk[crypto_sign_SECRETKEYBYTES]);

int keyfile_load(const char *path,
                 uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                 uint8_t sk[crypto_sign_SECRETKEYBYTES]);

void hex_encode(char *out, size_t outlen, const uint8_t *in, size_t inlen);
int  hex_decode(uint8_t *out, size_t outlen, const char *in);

#endif
