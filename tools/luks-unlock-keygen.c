#include "keyfile.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTPUT_KEYFILE\n"
                        "  generates an Ed25519 identity, writes the secret key\n"
                        "  to OUTPUT_KEYFILE (mode 0600), prints pubkey hex on stdout.\n",
                argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    keyfile_generate(pk, sk);

    if (keyfile_save(argv[1], sk) != 0) {
        sodium_memzero(sk, sizeof(sk));
        return 1;
    }
    sodium_memzero(sk, sizeof(sk));

    char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    hex_encode(hex, sizeof(hex), pk, sizeof(pk));
    printf("%s\n", hex);
    return 0;
}
