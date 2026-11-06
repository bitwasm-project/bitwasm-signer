#ifndef CORE_SIGHASH_H
#define CORE_SIGHASH_H

#include "plan.h"
#include "secp256k1.h"

/* BIP143 P2WPKH, SIGHASH_ALL only */
int sighash_bip143_p2wpkh(const plan_t *p, unsigned int index, const uint8_t pkh[20], uint8_t out[32]);
/* BIP143 P2WSH with the witness script as scriptCode, SIGHASH_ALL only */
int sighash_bip143_p2wsh(const plan_t *p, unsigned int index, const plan_wscript_t *ws, uint8_t out[32]);
/* The legacy (pre-segwit) digest, SIGHASH_ALL only, with code as input index's scriptCode: the previous output's
 * script for P2PKH, the redeem script for P2SH */
int sighash_legacy(const plan_t *p, unsigned int index, const uint8_t *code, size_t code_len, uint8_t out[32]);
/* BIP341 key path, no annex. hash_type is one of the seven BIP341 defines */
int sighash_bip341_keypath(const secp256k1_context *ctx, const plan_t *p, unsigned int index, uint8_t hash_type,
                           uint8_t out[32]);

#endif
