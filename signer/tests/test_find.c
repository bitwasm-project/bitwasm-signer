/* Finding which of our addresses an address is, and the address at an index, against BIP84's and BIP86's vectors */
#include <stdio.h>
#include <string.h>
#include "core.h"
#include "sha512.h"

static int checks, failures;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            failures++;                                                                                                \
            printf("FAIL ");                                                                                           \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while (0)

#define MN "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

/* receive (chain 0) is searched first, then change; the result is chain << 20 | index */
static int find(const char *addr, uint32_t count) {
    return core_find_address(addr, strlen(addr), 0, count);
}

/* core_address agrees with the vector and with core_find_address */
static int at(unsigned int purpose, uint32_t chain, uint32_t index, const char *want) {
    char got[ADDRESS_MAX];
    return core_address(purpose, 0, chain, index, got) == CORE_OK && !strcmp(got, want) &&
           find(want, index + 1) == (int)(chain << 20 | index);
}

int main(void) {
    uint8_t seed[64];
    pbkdf2_hmac_sha512((const uint8_t *)MN, sizeof(MN) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);

    CHECK(core_init(CORE_MAINNET), "init");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == -CORE_ERR_NO_SEED, "no seed");
    {
        char got[ADDRESS_MAX] = "x";
        CHECK(core_address(84, 0, 0, 0, got) == CORE_ERR_NO_SEED && !got[0], "address, no seed");
    }
    CHECK(core_load_seed(seed), "load");

    CHECK(at(84, 0, 0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), "address BIP84 0/0");
    CHECK(at(84, 0, 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), "address BIP84 0/1");
    CHECK(at(84, 1, 0, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"), "address BIP84 1/0");
    CHECK(at(86, 0, 0, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"), "address BIP86 0/0");
    CHECK(at(86, 1, 0, "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"), "address BIP86 1/0");
    CHECK(at(49, 1, 0, "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7"), "address BIP49 1/0");
    /* BIP44's P2PKH, as embit derives it */
    CHECK(at(44, 0, 0, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"), "address BIP44 0/0");
    CHECK(at(44, 1, 3, "1DzVLMA4HzjXPAr6aZoaacDPHXXntsZ2zL"), "address BIP44 1/3");
    CHECK(find("1DzVLMA4HzjXPAr6aZoaacDPHXXntsZ2zL", 10) == (1 << 20 | 3), "a P2PKH address is found");
    CHECK(find("mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV", 10) == -CORE_ERR_FORMAT, "testnet P2PKH on mainnet");
    {
        char got[ADDRESS_MAX] = "x";
        CHECK(core_address(48, 0, 0, 0, got) == CORE_ERR_FORMAT, "address, multisig refused");
        CHECK(core_address(84, 0, 2, 0, got) == CORE_ERR_FORMAT, "address, chain 2");
        CHECK(core_address(84, 0, 0, 100000, got) == CORE_ERR_FORMAT, "address, index we would not call ours");
        CHECK(core_address(84, 0x80000000u, 0, 0, got) == CORE_ERR_FORMAT, "address, hardened account");
        CHECK(core_address(84, 1, 0, 0, got) == CORE_OK && strcmp(got, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
              "address, another account");
    }

    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == 0, "BIP84 0/0");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 10) == 1, "BIP84 0/1");
    CHECK(find("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", 10) == (1 << 20), "BIP84 1/0");
    CHECK(find("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", 10) == 0, "BIP86 0/0");
    CHECK(find("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", 10) == 1, "BIP86 0/1");
    CHECK(find("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", 10) == (1 << 20), "BIP86 1/0");
    CHECK(find("BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G", 10) == 1, "upper case, as a QR carries it");
    /* BIP49, in base58, whose case is part of the address: the change in own_mixed_p2sh_nwu, m/49'/0'/0'/1/0 */
    CHECK(find("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", 10) == (1 << 20), "BIP49 1/0");
    CHECK(find("34K56KSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", 10) == -CORE_ERR_NOT_FOUND,
          "base58 with one letter's case changed is not ours");
    CHECK(find("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ0", 10) == -CORE_ERR_FORMAT, "0 is not base58");

    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 1) == -CORE_ERR_NOT_FOUND, "beyond count");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 1, 10) == -CORE_ERR_NOT_FOUND,
          "another account");
    /* the BIP173 P2WSH example: ours in form, not in key */
    CHECK(find("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 10) == -CORE_ERR_NOT_FOUND,
          "P2WSH is not found");

    CHECK(find("BC1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 10) == -CORE_ERR_FORMAT, "mixed case");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 10) == -CORE_ERR_FORMAT, "testnet on mainnet");
    CHECK(find("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 10) == -CORE_ERR_NOT_FOUND, "someone else's P2PKH");
    CHECK(find("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 10) == -CORE_ERR_FORMAT, "witness v2");
    CHECK(find("", 10) == -CORE_ERR_FORMAT, "empty");
    /* a NUL ends the address strcmp would see, and whatever follows it must not pass unread */
    CHECK(core_find_address("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g\0junk", 47, 0, 10) == -CORE_ERR_FORMAT,
          "a NUL inside refused");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g!", 10) == -CORE_ERR_FORMAT, "a character bech32 lacks");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9", 100000) == -CORE_ERR_NOT_FOUND,
          "a truncated address is not found, without searching");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0) == -CORE_ERR_FORMAT, "count 0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 100001) == -CORE_ERR_FORMAT, "count too large");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 0x80000000u, 10) == -CORE_ERR_FORMAT,
          "hardened account");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 10) == 0, "testnet BIP84 0/0");
    CHECK(find("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", 10) == 0, "BIP49's own testnet vector, m/49'/1'/0'/0/0");
    CHECK(at(84, 0, 0, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"), "address testnet BIP84 0/0");
    CHECK(at(49, 0, 0, "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"), "address testnet BIP49 0/0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == -CORE_ERR_FORMAT, "mainnet on testnet");

    core_unload();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
