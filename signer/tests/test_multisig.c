/* Registering a P2WSH sortedmulti wallet: the three formats it comes in, what makes one refused, and the
 * descriptor and addresses it gives back, against Bitcoin Core's getdescriptorinfo and deriveaddresses */
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

/* abandon x11 + about (ours), zoo x11 + wrong, legal winner ... yellow, each at m/48'/0'/0'/2' */
#define XPUB0                                                                                                          \
    "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf"
#define XPUB1                                                                                                          \
    "xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr"
#define XPUB2                                                                                                          \
    "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX"
/* letter advice ... above, someone else's */
#define XPUB3                                                                                                          \
    "xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6"
#define K0 "[73c5da0a/48h/0h/0h/2h]" XPUB0
#define K1 "[3f635a63/48h/0h/0h/2h]" XPUB1
#define K2 "[b8688df1/48h/0h/0h/2h]" XPUB2
#define K3 "[28645006/48h/0h/0h/2h]" XPUB3
#define DESC "wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))"
/* Core's getdescriptorinfo checksum, and its deriveaddresses for receive index 0 */
#define CHECKSUM "d9p6ar8k"
#define RECEIVE0 "bc1qea2gkgeszr7wm66x2ejkgdxm9nhg9462sszn75zmkhazev0t02vs70kkll"

/* Liana: ours primary with a year's recovery; ours the recovery on <2;3>, as Liana numbers a key's second use; and
 * a timelock short enough to be OP_16. Checksums, addresses and scripts from Core's getdescriptorinfo,
 * deriveaddresses and getaddressinfo */
#define LIANA1 "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(52596))))"
#define LIANA1_SUM "49ltg9qz"
#define LIANA1_RECEIVE0 "bc1qvyescgnual500mg9hygc99t5d3tmn6wmtrlh6dnq72pflh5svnmqaf0qnf"
#define LIANA1_RECEIVE0_WS                                                                                             \
    "2103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e0ac736476a914a4181cd34eeca10b68629756cd51360d" \
    "5185a37088ad0374cd00b268"
#define LIANA1_RECEIVE0_SPK "002061330c227cefe8f7ed05b9118295746c57b9e9db58ff7d3660f2829fde9064f6"
#define LIANA1_CHANGE0_SPK "0020487c188623b2be1ec355add828ce149a89c943353a0513a07d929604453b89f9"
#define LIANA2 "wsh(or_d(pk(" K1 "/<0;1>/*),and_v(v:pkh(" K0 "/<2;3>/*),older(144))))"
#define LIANA2_SUM "l98cz9q9"
#define LIANA2_RECEIVE0 "bc1qrk8e4m6gk9mmmy762qy693gg00j7ucxpnyhsagz3hf9tq4kjxvlq0qakku"
#define LIANA2_RECEIVE0_WS                                                                                             \
    "210254689c4a585b8f3d9ddea8e9e68d0e8f49f75709fa6e7d075657573815958a81ac736476a9144b47031bbf50a9b3b7be4ecc548e0637" \
    "eee2434888ad029000b268"
#define LIANA2_RECEIVE0_SPK "00201d8f9aef48b177bd93da5009a2c5087be5ee60c1992f0ea051ba4ab056d2333e"
#define LIANA2_CHANGE0_SPK "002035d90ba0985584144f259babfb3827ca33a034d874343c06b25bf395bfbbd2ec"
#define LIANA3 "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(16))))"
#define LIANA3_SUM "7y2y6u58"
#define LIANA3_RECEIVE0 "bc1qkqvtrgp69x8a7jj6zfcqqfjzvk3cyrdt8qstxghhyclfgzrknp5s7hstwc"

/* The same or_d with v:pk and after(), as Nunchuk writes them: ours primary with a time-based older; ours the
 * recovery key at a block height; v:pkh with a time after() pushed in 4 bytes; and older() at its largest */
#define PK1 "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pk(" K1 "/<0;1>/*),older(4194432))))"
#define PK1_SUM "6ks84eyt"
#define PK1_RECEIVE0_WS                                                                                                \
    "2103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e0ac7364210254689c4a585b8f3d9ddea8e9e68d0e8f49" \
    "f7"                                                                                                               \
    "5709fa6e7d075657573815958a81ad03800040b268"
#define PK1_RECEIVE0_SPK "0020054a0d3cafcc7da91625e3ac21f5bb61d2f8b52e173ee365d1c5f7dec15b93a4"
#define PK1_CHANGE0_SPK "00208163ae5e4ebb025765c86d4316a64ff927f58dd131f6013336356966dee3dfe7"
#define PK2 "wsh(or_d(pk(" K1 "/<0;1>/*),and_v(v:pk(" K0 "/<2;3>/*),after(1000000))))"
#define PK2_SUM "4um5yfag"
#define PK2_RECEIVE0 "bc1qs3v3chanyx004vefg2x2anm5vll4kpd5pxasknw0sdhtppk27vyqfglwka"
#define PK2_RECEIVE0_WS                                                                                                \
    "210254689c4a585b8f3d9ddea8e9e68d0e8f49f75709fa6e7d075657573815958a81ac73642103e762c58a58500170daf6a9c73908744504" \
    "5c"                                                                                                               \
    "25b01eb1960e7f7ec3b770d5125cad0340420fb168"
#define PK2_RECEIVE0_SPK "002084591c5fb3219efab329428caecf7467ff5b05b409bb0b4dcf836eb086caf308"
#define PK2_CHANGE0_SPK "002088c2442495ef57646d6b71542f3c16802c2eb5aa517a59736f1ab35410204d4b"
#define AFTER3 "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),after(1700000000))))"
#define AFTER3_SUM "jq6a3ntc"
#define AFTER3_RECEIVE0 "bc1qruqcyg9n7gjlghdyuzmv30we59jx67f390ax0kghg762nfa30hrq9kzyw7"
#define OLDER4 "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(2147483647))))"
#define OLDER4_SUM "u74pe25a"
#define OLDER4_RECEIVE0 "bc1qkkka9qvtlfs24f9akyzasp76r4cc3jkpxahulsm6xr9wkf6k9zysg99nxx"

static core_multisig_t ms;

static int load(const char *text) {
    return core_multisig_load(text, strlen(text), &ms);
}

static unsigned int unhex(const char *h, uint8_t *out) {
    unsigned int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned int v;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

/* One Liana input of ours at <chain>/0, paying someone and sending change to our <change>/0 */
static plan_t liana_plan(const char *ws, const char *spk, uint32_t chain, const char *change_spk, uint32_t change) {
    plan_t p = {.magic = PLAN_MAGIC, .version = PLAN_VERSION, .tx_version = 2, .n_inputs = 1, .n_outputs = 2};
    const plan_keypath_t key = {6, 0x73c5da0a, {48 | 0x80000000u, 0x80000000u, 0x80000000u, 2 | 0x80000000u, chain, 0}};
    plan_input_t *in = &p.inputs[0];
    memset(in->prev_txid, 0x11, 32);
    in->amount = 100000, in->sequence = 0xfffffffd, in->key = key, in->sighash_type = 1;
    in->spk.len = (uint8_t)unhex(spk, in->spk.bytes);
    p.wscripts[0].len = (uint8_t)unhex(ws, p.wscripts[0].bytes);
    p.outputs[0].amount = 60000;
    p.outputs[0].spk.len = (uint8_t)unhex("0014751e76e8199196d454941c45d1b3a323f1433bd6", p.outputs[0].spk.bytes);
    p.outputs[1].amount = 39000;
    p.outputs[1].spk.len = (uint8_t)unhex(change_spk, p.outputs[1].spk.bytes);
    p.outputs[1].key = key, p.outputs[1].key.path[4] = change;
    return p;
}

static void liana(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_INPUTS];
    unsigned int n_sigs;
    plan_t p;
    char canonical[CORE_MULTISIG_DESC_MAX];

    CHECK(load(LIANA1) == CORE_OK && ms.kind == CORE_WALLET_OR_D && ms.n == 2 && ms.ours == 0 && ms.lock == 52596,
          "Liana: ours the primary key, recovery after 52596 blocks");
    CHECK(!strcmp(ms.descriptor, LIANA1 "#" LIANA1_SUM), "Liana descriptor with Core's checksum: %s", ms.descriptor);
    CHECK(!strcmp(ms.receive, LIANA1_RECEIVE0), "Liana's first receive address is Core's: %s", ms.receive);
    strcpy(canonical, ms.descriptor);
    CHECK(load(canonical) == CORE_OK && !strcmp(ms.descriptor, canonical), "its own Liana descriptor reads back");

    p = liana_plan(LIANA1_RECEIVE0_WS, LIANA1_RECEIVE0_SPK, 0, LIANA1_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[0] == CORE_OUT_EXTERNAL &&
              r.owner[1] == CORE_OUT_CHANGE && r.fee == 1000,
          "a Liana input signed with the primary key, its change recognised");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 && sigs[0].pubkey[0] == 0x03 &&
              !memcmp(sigs[0].pubkey + 1, p.wscripts[0].bytes + 2, 32),
          "the signature is by the script's pk() key");
    p.outputs[1].key.path[4] = 3;
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[1] == CORE_OUT_EXTERNAL,
          "change at a step Liana does not use");

    CHECK(load(LIANA2) == CORE_OK && ms.ours == 1 && ms.lock == 144 && !strcmp(ms.receive, LIANA2_RECEIVE0) &&
              !strcmp(ms.descriptor, LIANA2 "#" LIANA2_SUM),
          "Liana: ours the recovery key on <2;3>: %s", ms.receive);
    p = liana_plan(LIANA2_RECEIVE0_WS, LIANA2_RECEIVE0_SPK, 2, LIANA2_CHANGE0_SPK, 3);
    p.inputs[0].sequence = 144;
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE,
          "a Liana input signed with the recovery key, change on 3");
    p.inputs[0].key.path[4] = 0;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NOT_OURS, "the recovery key at the primary's step");

    CHECK(load(LIANA3) == CORE_OK && !strcmp(ms.receive, LIANA3_RECEIVE0) &&
              !strcmp(ms.descriptor, LIANA3 "#" LIANA3_SUM),
          "Liana with older(16), pushed as OP_16");
    CHECK(core_multisig_cbor((uint8_t[1024]){0}, 1024) == -CORE_ERR_FORMAT, "no crypto-output for a Liana wallet");

    core_multisig_unload();
    p = liana_plan(LIANA1_RECEIVE0_WS, LIANA1_RECEIVE0_SPK, 0, LIANA1_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[1] == CORE_OUT_EXTERNAL,
          "without the wallet, signed but its change shown as external");
    p.wscripts[0].bytes[63] ^= 1;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NOT_OURS, "a timelock that does not hash to the input's script");
    p.wscripts[0].bytes[0] = 0x20;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SCRIPT, "a script that is neither multisig nor Liana's");

    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(0))))") == CORE_ERR_FORMAT, "older(0)");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(2147483648))))") == CORE_ERR_FORMAT,
          "older() at 2^31, beyond what miniscript takes");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pk(" K1 "/<0;1>/*),after(0))))") == CORE_ERR_FORMAT, "after(0)");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkhh(" K1 "/<0;1>/*),older(144))))") == CORE_ERR_FORMAT,
          "neither v:pk nor v:pkh");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<1;1>/*),older(144))))") == CORE_ERR_FORMAT,
          "receive and change on the same step");
    CHECK(load("wsh(or_d(pk(" K3 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(144))))") == CORE_ERR_WALLET,
          "a Liana wallet without our key");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K0 "/<2;3>/*),older(144))))") == CORE_ERR_FORMAT,
          "our xpub as both keys");
    CHECK(load("wsh(sortedmulti(2," K0 "/<2;3>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "sortedmulti keeps receive 0, change 1");
}

static void or_d_variants(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_INPUTS];
    unsigned int n_sigs;
    plan_t p;

    CHECK(load(PK1) == CORE_OK && ms.kind == (CORE_WALLET_OR_D | CORE_WALLET_OR_D_PK) && ms.ours == 0 &&
              ms.lock == 4194432 && !strcmp(ms.descriptor, PK1 "#" PK1_SUM),
          "v:pk with a time-based older(): %s", ms.descriptor);
    p = liana_plan(PK1_RECEIVE0_WS, PK1_RECEIVE0_SPK, 0, PK1_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE,
          "a v:pk input signed with the primary key, its change recognised");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 1, 33),
          "the signature is by the pk() key");

    CHECK(load(PK2) == CORE_OK && ms.kind == (CORE_WALLET_OR_D | CORE_WALLET_OR_D_PK | CORE_WALLET_OR_D_AFTER) &&
              ms.ours == 1 && ms.lock == 1000000 && !strcmp(ms.receive, PK2_RECEIVE0) &&
              !strcmp(ms.descriptor, PK2 "#" PK2_SUM),
          "v:pk with after() at a height, ours the recovery key: %s", ms.receive);
    p = liana_plan(PK2_RECEIVE0_WS, PK2_RECEIVE0_SPK, 2, PK2_CHANGE0_SPK, 3);
    p.locktime = 1000000;
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE,
          "a v:pk input signed with the recovery key, change on 3");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 38, 33),
          "the signature is by the v:pk() key");
    p.wscripts[0].bytes[p.wscripts[0].len - 2] = 0xb2;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NOT_OURS, "CSV in place of CLTV does not hash to the input's script");

    CHECK(load(AFTER3) == CORE_OK && ms.kind == (CORE_WALLET_OR_D | CORE_WALLET_OR_D_AFTER) &&
              !strcmp(ms.receive, AFTER3_RECEIVE0) && !strcmp(ms.descriptor, AFTER3 "#" AFTER3_SUM),
          "v:pkh with a time after(), pushed in 4 bytes");
    CHECK(load(OLDER4) == CORE_OK && !strcmp(ms.receive, OLDER4_RECEIVE0) &&
              !strcmp(ms.descriptor, OLDER4 "#" OLDER4_SUM),
          "older(2^31 - 1)");

    core_multisig_unload();
    p = liana_plan(PK1_RECEIVE0_WS, PK1_RECEIVE0_SPK, 0, PK1_CHANGE0_SPK, 1);
    p.wscripts[0].bytes[p.wscripts[0].len - 3] = 0x00;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SCRIPT, "a timelock pushed with a needless zero byte");
}

int main(void) {
    uint8_t seed[64], cbor[1024], mainnet_cbor[1024];
    static const char mn[] =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char canonical[CORE_MULTISIG_DESC_MAX];
    int n, mainnet_cbor_len = 0;

    pbkdf2_hmac_sha512((const uint8_t *)mn, sizeof(mn) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);
    CHECK(core_init(CORE_MAINNET) && core_load_seed(seed), "load mainnet");

    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "no wallet, no crypto-output");
    CHECK(load(DESC) == CORE_OK, "a descriptor");
    CHECK(ms.threshold == 2 && ms.n == 3 && ms.ours == 0, "2 of 3, ours first");
    {
        core_facts_t f;
        CHECK(core_facts(&(plan_t){0}, &f) == CORE_OK && f.wallet, "facts say a wallet is registered");
    }
    CHECK(ms.fingerprints[1] == 0x3f635a63 && ms.fingerprints[2] == 0xb8688df1, "the cosigners' fingerprints");
    CHECK(!strcmp(ms.receive, RECEIVE0), "the first receive address is Core's: %s", ms.receive);
    CHECK(!strcmp(ms.descriptor, DESC "#" CHECKSUM), "the descriptor with Core's checksum: %s", ms.descriptor);
    strcpy(canonical, ms.descriptor);
    CHECK(load(canonical) == CORE_OK && !strcmp(ms.descriptor, canonical), "its own descriptor reads back");
    canonical[strlen(canonical) - 1] ^= 1;
    CHECK(load(canonical) == CORE_ERR_FORMAT, "a wrong checksum");

    CHECK(load("wsh(sortedmulti(2," K1 "/**," K0 "/**," K2 "/**))") == CORE_OK && ms.ours == 1 &&
              !strcmp(ms.receive, RECEIVE0),
          "BSMS's /** and another key order give the same wallet");
    CHECK(load("wsh(sortedmulti(2,[73C5DA0A/48'/0'/0'/2']" XPUB0 "/0/*," K1 "/0/*," K2 "/0/*))") == CORE_OK &&
              !strcmp(ms.descriptor, DESC "#" CHECKSUM),
          "' and capitals in the origin, and /0/*");

    CHECK(load("BSMS 1.0\n" DESC "\n/0/*,/1/*\n" RECEIVE0 "\n") == CORE_OK, "BSMS");
    CHECK(load("BSMS 1.0\r\n" DESC
               "\r\nNo path restrictions\r\nBC1QEA2GKGESZR7WM66X2EJKGDXM9NHG9462SSZN75ZMKHAZEV0T02VS70KKLL") == CORE_OK,
          "BSMS with CRLF and an upper-case address");
    CHECK(load("BSMS 1.0\n" DESC "\n/0/*,/1/*\nbc1qc6p3lpt2e2wv0vukgyykx3ca8fhy6pvlfg7sgv8e3qej473jjmxs29860y") ==
              CORE_ERR_WALLET,
          "BSMS whose address is the first change address, not receive");
    CHECK(load("BSMS 1.1\n" DESC "\n/0/*,/1/*\n" RECEIVE0) == CORE_ERR_FORMAT, "another BSMS version");

    CHECK(load("# Coldcard Multisig setup file (created by Sparrow)\n#\nName: test\nPolicy: 2 of 3\n"
               "Derivation: m/48'/0'/0'/2'\nFormat: P2WSH\n\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1 "\nB8688DF1: " XPUB2
               "\n") == CORE_OK &&
              !strcmp(ms.descriptor, DESC "#" CHECKSUM),
          "a Coldcard setup file");
    CHECK(load("Policy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2SH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1
               "\nB8688DF1: " XPUB2) == CORE_ERR_FORMAT,
          "a setup file for P2SH");
    CHECK(load("Policy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1) ==
              CORE_ERR_FORMAT,
          "a setup file with fewer keys than its policy");
    CHECK(load("Policy: 2 of 3\nFormat: P2WSH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1 "\nB8688DF1: " XPUB2) ==
              CORE_ERR_FORMAT,
          "a setup file without a derivation");

    CHECK(load("wsh(sortedmulti(2," K3 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))") == CORE_ERR_WALLET,
          "a wallet without our key");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2h]" XPUB3 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_WALLET,
          "our fingerprint on someone else's key, as with the wrong passphrase");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/1h/2h]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_WALLET,
          "our key at an origin it was not derived at");
    CHECK(load("wsh(sortedmulti(2," K0 "/<0;1>/*," K0 "/<0;1>/*))") == CORE_ERR_FORMAT, "a key twice");
    CHECK(load("wsh(sortedmulti(4," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "a threshold above the keys");
    CHECK(load("wsh(sortedmulti(1," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "four keys");
    CHECK(load("wsh(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT, "multi() rather than sortedmulti()");
    CHECK(load("sh(wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/<0;1>/*)))") == CORE_ERR_FORMAT, "P2SH-P2WSH");
    CHECK(load("wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/2/*))") == CORE_ERR_FORMAT, "a child other than 0 or 1");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "an unhardened origin step");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "an origin shallower than the xpub");
    {
        char bad[] = DESC;
        bad[strstr(bad, "xpub6DkF") - bad + 20] ^= 1;
        CHECK(load(bad) == CORE_ERR_FORMAT, "an xpub with a broken base58 checksum");
    }

    CHECK(load(DESC) == CORE_OK, "loaded again");
    n = core_multisig_cbor(cbor, sizeof(cbor));
    CHECK(n > 0 && cbor[0] == 0xd9 && cbor[1] == 0x01 && cbor[2] == 0x91 && cbor[3] == 0xd9 && cbor[4] == 0x01 &&
              cbor[5] == 0x97,
          "crypto-output starts wsh (401), sortedmulti (407)");
    if (n > 0 && (size_t)n <= sizeof(mainnet_cbor)) {
        memcpy(mainnet_cbor, cbor, (size_t)n);
        mainnet_cbor_len = n;
    }
    CHECK(core_multisig_load_cbor(cbor, (size_t)n, &ms) == CORE_OK && !strcmp(ms.descriptor, DESC "#" CHECKSUM) &&
              !strcmp(ms.receive, RECEIVE0),
          "crypto-output CBOR registers the same wallet and receive address");
    CHECK(core_multisig_load_cbor(cbor, 1, &ms) == CORE_ERR_FORMAT &&
              core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET,
          "malformed crypto-output leaves no registered wallet");
    CHECK(load(DESC) == CORE_OK, "descriptor reloads after malformed CBOR");
    n = core_account_cbor(0, cbor, sizeof(cbor));
    CHECK(n > 0 && cbor[0] == 0xa2 && cbor[1] == 0x01 && cbor[2] == 0x1a && cbor[3] == 0x73 && cbor[7] == 0x02 &&
              cbor[8] == 0x84,
          "crypto-account: our fingerprint and four outputs");
    CHECK(core_account_cbor(0, cbor, 100) == -CORE_ERR_FORMAT, "a buffer too small");
    liana();
    or_d_variants();

    core_unload();
    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "unloading the seed unloads the wallet");
    CHECK(load(DESC) == CORE_ERR_NO_SEED, "no seed, no wallet");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(load(DESC) == CORE_ERR_FORMAT, "a mainnet xpub on testnet");
    CHECK(mainnet_cbor_len > 0 &&
              core_multisig_load_cbor(mainnet_cbor, (size_t)mainnet_cbor_len, &ms) == CORE_ERR_FORMAT,
          "mainnet crypto-output is refused on testnet");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
