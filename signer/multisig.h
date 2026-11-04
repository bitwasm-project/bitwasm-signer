#ifndef CORE_MULTISIG_H
#define CORE_MULTISIG_H

/* A P2WSH sortedmulti wallet of at most three keys, read from a coordinator's descriptor, BSMS record or
 * Coldcard-style setup file, or Liana's primary key with a timelocked recovery key. Only public keys: core.c
 * decides which of them is ours */

#include <stddef.h>
#include <stdint.h>
#include "plan.h"
#include "address.h"

#define MS_MAX_KEYS 3
#define MS_MAX_DEPTH (PLAN_MAX_DEPTH - 2) /* the origin path, leaving room for chain and index */
#define MS_DESC_MAX 640

typedef struct {
    uint32_t fingerprint;
    uint32_t path[MS_MAX_DEPTH]; /* all hardened */
    uint8_t depth;
    uint32_t child[2]; /* the receive and change steps after the xpub: <0;1> unless Liana says <2;3> or so */
    uint8_t ser[78];   /* the xpub as serialized: chain code at 13, public key at 45 */
} ms_key_t;

/* OR_D is wsh(or_d(pk(keys[0]),and_v(v:pkh(keys[1]),older(lock)))) as Liana writes it. The flags swap in
 * v:pk(keys[1]) and after(lock), as Nunchuk can write it */
enum { MS_SORTEDMULTI = 0, MS_OR_D = 1, MS_OR_D_PK = 2, MS_OR_D_AFTER = 4 };

typedef struct {
    uint8_t kind, threshold, n;
    uint32_t lock; /* OR_D: the older() or after() value, 1 to 2^31 - 1 */
    ms_key_t keys[MS_MAX_KEYS];
} ms_wallet_t;

/* 1 on success. address is the first receive address a BSMS record states, or empty */
int ms_parse(const char *s, size_t len, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]);
/* Accepts BCR-2020-010 crypto-output CBOR for the firmware's BIP48 multipath sortedmulti wallets */
int ms_cbor_descriptor(const uint8_t *cbor, size_t len, int testnet, char out[MS_DESC_MAX]);
/* The witness script at chain (0 receive, 1 change) and index, keys sorted as sortedmulti() sorts them */
int ms_wscript(const ms_wallet_t *w, uint32_t chain, uint32_t index, plan_wscript_t *out);
/* n as the script pushes it, a minimal script number: OP_1..OP_16, or 1 to 4 bytes. Returns its length */
size_t ms_scriptnum(uint32_t n, uint8_t out[5]);
/* The wallet's descriptor with xpub / tpub, each key's <a;b> children and its checksum. Returns its length, or 0 */
size_t ms_descriptor(const ms_wallet_t *w, int testnet, char out[MS_DESC_MAX]);

#endif
