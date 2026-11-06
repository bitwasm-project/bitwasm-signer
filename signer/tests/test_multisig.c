/* Registering a P2WSH sortedmulti or multi wallet: the three formats it comes in, what makes one refused, and the
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
#define UPPER0 "BC1QEA2GKGESZR7WM66X2EJKGDXM9NHG9462SSZN75ZMKHAZEV0T02VS70KKLL"
#define CHANGE0 "bc1qc6p3lpt2e2wv0vukgyykx3ca8fhy6pvlfg7sgv8e3qej473jjmxs29860y"

/* all x12 and abandon x23 art, at m/48'/0'/0'/2': with them six keys, the most the plan's witness script holds.
 * Checksums and addresses from Core; witness scripts hash to its addresses */
#define K4                                                                                                             \
    "[5c9e228d/48h/0h/0h/2h]"                                                                                          \
    "xpub6EgGHjcvovyN3nK921zAGPfuB41cJXkYRdt3tLGmiMyvbgHpss4X1eRZwShbEBb1znz2e2bCkCED87QZpin3sSYKbmCzQ9Sc7LaV98ngdeX"
#define K5                                                                                                             \
    "[5436d724/48h/0h/0h/2h]"                                                                                          \
    "xpub6E79FaRWLSJCAgA2jDHRvyrWKwT6aSmR685zptzyYPvmUd44omcxZ1NAzDtbdFBvEADjcVbV4NzTDwQeU6oiSV9KGiMSWhjANZjbfUHkm3Y"
#define SORTED6                                                                                                        \
    "wsh(sortedmulti(3," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*," K4 "/<0;1>/*," K5 "/<0;1>/*))"
#define SORTED6_SUM "zdum4404"
#define SORTED6_RECEIVE0 "bc1qg6qmu2dvyjsjjtvvl8r9els29qkaw2mxt2ewymmxtvqe3s5mmlmqm7aary"
#define SORTED6_RECEIVE0_WS                                                                                            \
    "53210254689c4a585b8f3d9ddea8e9e68d0e8f49f75709fa6e7d075657573815958a8121028e818df63d6f2dce9308d7455fd4c85cbb39d7" \
    "03608b8fbed647d75e262322d82103229cb34fe3eb1af43b6dd2a2e1b31681039b71d9303ded36b3128ef359e379bd21032c612ce1300e68" \
    "92508903ff7141a9c608a18ac95423239f33c57b5b6e143ad42103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626" \
    "c514e02103f9c2483ba111f98f01a51e748c75b3ab37429288c31526ee15453482631aed2156ae"
#define SORTED6_RECEIVE0_SPK "00204681be29ac24a1292d8cf9c65cfe0a282dd72b665ab2e26f665b0198c29bdff6"
#define SORTED6_CHANGE0 "bc1q4wr6hnpa2v9zjjgajdxemk0dm4m5reuszdgayza8pxuuvr655v9swch45e"
#define SORTED6_CHANGE0_SPK "0020ab87abcc3d530a29491d934d9dd9eddd7741e7901351d20ba709b9c60f54a30b"
#define MULTI3 "wsh(multi(2," K1 "/<0;1>/*," K0 "/<0;1>/*," K2 "/<0;1>/*))"
#define MULTI3_SUM "m7ne0ae8"
#define MULTI3_RECEIVE0 "bc1qp40943ackp4r0rlux4nunfgxrlg8rmp97gae53svywxut7thskwskjycjv"
#define MULTI3_CHANGE0 "bc1qxljh3pklsjrxfmm3rlkvn0t97x8mckmaztrp769jwhl5s4s76qsqlvj6uj"
#define MULTI6 "wsh(multi(4," K5 "/<0;1>/*," K4 "/<0;1>/*," K3 "/<0;1>/*," K2 "/<0;1>/*," K1 "/<0;1>/*," K0 "/<0;1>/*))"
#define MULTI6_SUM "qealnls8"
#define MULTI6_RECEIVE0 "bc1qvtwe0kpccz8dqjfxhj6xkrgch9en8lvwsld24m5wg344ln74p88ssppvty"
#define MULTI6_RECEIVE0_WS                                                                                             \
    "5421032c612ce1300e6892508903ff7141a9c608a18ac95423239f33c57b5b6e143ad42103f9c2483ba111f98f01a51e748c75b3ab374292" \
    "88c31526ee15453482631aed212103229cb34fe3eb1af43b6dd2a2e1b31681039b71d9303ded36b3128ef359e379bd21028e818df63d6f2d" \
    "ce9308d7455fd4c85cbb39d703608b8fbed647d75e262322d8210254689c4a585b8f3d9ddea8e9e68d0e8f49f75709fa6e7d075657573815" \
    "958a812103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e056ae"
#define MULTI6_RECEIVE0_SPK "002062dd97d838c08ed04926bcb46b0d18b97333fd8e87daaaee8e446b5fcfd509cf"
#define MULTI6_CHANGE0_SPK "0020be3c4e715015c8810d307b553bd5bd6a3fb3ab766ae0b36a768ff885f0497831"

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

/* With multi(): Keeper's Emergency Key, ours in the 2-of-3; and two 2-of-3s at the plan's 219 bytes, ours on the
 * recovery path beside two keys of account 1 */
#define K1A                                                                                                            \
    "[3f635a63/48h/0h/1h/"                                                                                             \
    "2h]"                                                                                                              \
    "xpub6EM8uMGUZMyVPM95MyiJKaQF476QWxmZZExfShr3eARKprqgqvS9m4ozAPZe4SBAbuBiRxy3QAuYcduqybq2vgXDVpvaioHDVaHbZTxnDMT"
#define K2A                                                                                                            \
    "[b8688df1/48h/0h/1h/"                                                                                             \
    "2h]"                                                                                                              \
    "xpub6EAMBJLn1jiquajTsNRkZXU1oKnA4WJMNvcz4FRR4QmFKdfHxJVvfRLoysWfcc16AMTR4CoMD8UNjvs9JtbsLeuLwpTczgq8zuuERnp8YZF"
#define EK "wsh(or_d(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*),and_v(v:pkh(" K3 "/<0;1>/*),after(900000))))"
#define EK_SUM "n62ygf4f"
#define EK_RECEIVE0 "bc1qfyy5qqadpynnnkr9qv0w2mdaq5ksvplv87mds7y7msyvxfvwx4gsqdg548"
#define EK_RECEIVE0_WS                                                                                                 \
    "522103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e0210254689c4a585b8f3d9ddea8e9e68d0e8f49f7"   \
    "5709fa6e7d075657573815958a8121028e818df63d6f2dce9308d7455fd4c85cbb39d703608b8fbed647d75e262322d853ae736476a914"   \
    "cac00799cd0755d9d2d68455eb8f984a64184e6788ad03a0bb0db168"
#define EK_RECEIVE0_SPK "002049094003ad092739d865031ee56dbd052d0607ec3fb6d8789edc08c3258e3551"
#define EK_CHANGE0_SPK "002021bc2d18717e4dd71ed7b8c3021949d7d7be93218cd18ae9ac931d3bb6a5f110"
#define MX                                                                                                             \
    "wsh(or_d(multi(2," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*),and_v(v:multi(2," K0 "/<2;3>/*," K1A               \
    "/<0;1>/*," K2A "/<0;1>/*),after(1700000000))))"
#define MX_SUM "4jxfv582"
#define MX_RECEIVE0 "bc1qjp5pmxw4qvf888qdf8lcda7jgcaffc82nl4035shnq6z6rmxnlmskahf27"
#define MX_RECEIVE0_WS                                                                                                 \
    "52210254689c4a585b8f3d9ddea8e9e68d0e8f49f75709fa6e7d075657573815958a8121028e818df63d6f2dce9308d7455fd4c85cbb39"   \
    "d703608b8fbed647d75e262322d82103229cb34fe3eb1af43b6dd2a2e1b31681039b71d9303ded36b3128ef359e379bd53ae7364522103"   \
    "e762c58a58500170daf6a9c739087445045c25b01eb1960e7f7ec3b770d5125c21027fea83cba9510d4c21bf9fa7fca1d10f9e116a9236"   \
    "53830d9c1dec41b70ea30c2102a6dd7f84904c4dd24d242cd35053595f911d48fd4f07cfc78420895e12704c8953af0400f15365b168"
#define MX_RECEIVE0_SPK "002090681d99d50312739c0d49ff86f7d2463a94e0ea9feaf8d21798342d0f669ff7"
#define MX_CHANGE0_SPK "0020a8b5bc019053b5847fad2131790ee63526aed1727d8881d654e02cebe2ec0dd3"

/* Our key on both paths, as Nunchuk and Liana reuse a signer: a 2-of-3 decaying to 1-of-3 over the same three
 * xpubs at <2;3>, and Liana's pk() with our own pkh() for recovery */
#define DECAY                                                                                                          \
    "wsh(or_d(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*),and_v(v:multi(1," K0 "/<2;3>/*," K1 "/<2;3>/*," K2 \
    "/<2;3>/*),older(4320))))"
#define DECAY_SUM "fsuq87rv"
#define DECAY_RECEIVE0 "bc1q4r8awzd8ypq7epw4d8v7cj7j2c9vjef6r2plz6ckwsel807l67dqn24nl8"
#define DECAY_RECEIVE0_WS                                                                                              \
    "522103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e0210254689c4a585b8f3d9ddea8e9e68d0e8f49f7"   \
    "5709fa6e7d075657573815958a8121028e818df63d6f2dce9308d7455fd4c85cbb39d703608b8fbed647d75e262322d853ae7364512103"   \
    "e762c58a58500170daf6a9c739087445045c25b01eb1960e7f7ec3b770d5125c2103238910fbaf17e60ce3deb186fe376f59e6797ee486"   \
    "66a7edcf18538d596428752102143716d9363b54bb8d74b3b397d55c04634d90ffe10663408bc7876060858fa453af02e010b268"
#define DECAY_RECEIVE0_SPK "0020a8cfd709a72041ec85d569d9ec4bd2560ac9653a1a83f16b167433f3bfdfd79a"
#define DECAY_CHANGE0_SPK "00205bcad66602c03834f86d9c8a2d8caa871256f246970b0895d8a930ef3b0176ed"
#define SELF "wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K0 "/<2;3>/*),older(144))))"
#define SELF_SUM "stvwpa2k"
#define SELF_RECEIVE0_WS                                                                                               \
    "2103dc1953c2756c7c58d4f48ca1bbba767f414fd236bf4d662b67721ac626c514e0ac736476a9144b47031bbf50a9b3b7be4ecc548e06"   \
    "37eee2434888ad029000b268"
#define SELF_RECEIVE0_SPK "002054ede26b0a7790a603a7acfd43e3cf071ebf42fb3b4d9646c6dc2724c10180fd"
#define SELF_CHANGE0_SPK "00207705e6ceb78c747993ec00b89df543549ad1f65696da380d76a4d91bffb632dd"

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
    core_sig_t sigs[PLAN_MAX_SIGS];
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
    CHECK(load("wsh(sortedmulti(2," K0 "/<2;3>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "sortedmulti keeps receive 0, change 1");
}

static void or_d_variants(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_SIGS];
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

static void or_d_multi(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_SIGS];
    unsigned int n_sigs;
    plan_t p;

    CHECK(load(EK) == CORE_OK && ms.kind == (CORE_WALLET_OR_D | CORE_WALLET_OR_D_AFTER) && ms.n == 4 &&
              ms.primary == 3 && ms.threshold == 2 && ms.threshold2 == 1 && ms.ours == 0 && ms.lock == 900000 &&
              ms.fingerprints[3] == 0x28645006 && !strcmp(ms.receive, EK_RECEIVE0) &&
              !strcmp(ms.descriptor, EK "#" EK_SUM),
          "Keeper's Emergency Key, ours in the 2-of-3: %s", ms.descriptor);
    p = liana_plan(EK_RECEIVE0_WS, EK_RECEIVE0_SPK, 0, EK_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE,
          "an input of it signed, its change recognised");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 2, 33),
          "the signature is by our key in the multi()");

    CHECK(load(MX) == CORE_OK && ms.n == 6 && ms.primary == 3 && ms.threshold2 == 2 && ms.ours == 3 &&
              !strcmp(ms.receive, MX_RECEIVE0) && !strcmp(ms.descriptor, MX "#" MX_SUM),
          "two 2-of-3s, ours on the recovery path: %s", ms.receive);
    p = liana_plan(MX_RECEIVE0_WS, MX_RECEIVE0_SPK, 2, MX_CHANGE0_SPK, 3);
    p.locktime = 1700000000;
    CHECK(p.wscripts[0].len == PLAN_MAX_WSCRIPT && core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 &&
              r.owner[1] == CORE_OUT_CHANGE,
          "a 219-byte witness script signed on the recovery path");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 109, 33),
          "the signature is by our key in the v:multi()");

    core_multisig_unload();
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1, "without the wallet, the same input is signed");
    p.wscripts[0].bytes[107 + 1 + 3 * 34 + 1] = 0xae; /* after the primary's 105 bytes, IFDUP NOTIF */
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SCRIPT, "CHECKMULTISIG for the recovery path's VERIFY");
    p = liana_plan(MX_RECEIVE0_WS, MX_RECEIVE0_SPK, 2, MX_CHANGE0_SPK, 3);
    p.wscripts[0].bytes[0] = 0x54;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SCRIPT, "a threshold above the side's key count");

    CHECK(load("wsh(or_d(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*),and_v(v:pkh(" K1A
               "/<0;1>/*),after(900000))))") == CORE_ERR_FORMAT,
          "four keys on one side");
    CHECK(load("wsh(or_d(multi(1," K0 "/<0;1>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(144))))") == CORE_ERR_FORMAT,
          "multi() of one key, which pk() writes");
    CHECK(load("wsh(or_d(multi(3," K0 "/<0;1>/*," K1 "/<0;1>/*),and_v(v:pkh(" K2 "/<0;1>/*),older(144))))") ==
              CORE_ERR_FORMAT,
          "a threshold above the side's key count");
    CHECK(load("wsh(or_d(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*),and_v(v:pkh(" K3 "/<0;1>/*),older(144))))") ==
                  CORE_OK &&
              ms.n == 3 && ms.primary == 2,
          "a 2-of-2 with one recovery key");
}

/* Up to six keys, sorted or in multi()'s order, as upstream SeedSigner takes them */
static void wide(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_SIGS];
    unsigned int n_sigs;
    plan_t p;
    uint8_t cbor[1024];
    char addr[ADDRESS_MAX], canonical[CORE_MULTISIG_DESC_MAX];
    int n;

    CHECK(load(SORTED6) == CORE_OK && ms.kind == CORE_WALLET_SORTEDMULTI && ms.n == 6 && ms.threshold == 3 &&
              ms.ours == 0 && ms.fingerprints[5] == 0x5436d724 && !strcmp(ms.receive, SORTED6_RECEIVE0) &&
              !strcmp(ms.descriptor, SORTED6 "#" SORTED6_SUM),
          "a 3-of-6 sortedmulti: %s", ms.receive);
    CHECK(core_multisig_address(1, 0, addr) == CORE_OK && !strcmp(addr, SORTED6_CHANGE0), "its change 0: %s", addr);
    p = liana_plan(SORTED6_RECEIVE0_WS, SORTED6_RECEIVE0_SPK, 0, SORTED6_CHANGE0_SPK, 1);
    CHECK(p.wscripts[0].len == 207 && core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 &&
              r.owner[1] == CORE_OUT_CHANGE,
          "an input of it signed, its change recognised");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 2 + 4 * 34, 33),
          "the signature is by our key, fifth once sorted");

    CHECK(load(MULTI3) == CORE_OK && ms.kind == CORE_WALLET_MULTI && ms.ours == 1 &&
              !strcmp(ms.receive, MULTI3_RECEIVE0) && !strcmp(ms.descriptor, MULTI3 "#" MULTI3_SUM),
          "multi() keeps its keys' order: %s", ms.receive);
    CHECK(core_multisig_address(1, 0, addr) == CORE_OK && !strcmp(addr, MULTI3_CHANGE0), "its change 0: %s", addr);
    strcpy(canonical, ms.descriptor);
    CHECK(load(canonical) == CORE_OK && !strcmp(ms.descriptor, canonical), "its own multi() descriptor reads back");
    n = core_multisig_cbor(cbor, sizeof(cbor));
    CHECK(n > 5 && cbor[3] == 0xd9 && cbor[4] == 0x01 && cbor[5] == 0x96, "crypto-output with multi (406)");
    CHECK(core_multisig_load_cbor(cbor, (size_t)n, &ms) == CORE_OK && ms.kind == CORE_WALLET_MULTI &&
              !strcmp(ms.descriptor, MULTI3 "#" MULTI3_SUM),
          "which registers the same multi() wallet");

    CHECK(load(MULTI6) == CORE_OK && ms.n == 6 && ms.ours == 5 && !strcmp(ms.receive, MULTI6_RECEIVE0) &&
              !strcmp(ms.descriptor, MULTI6 "#" MULTI6_SUM),
          "a 4-of-6 multi(), ours last: %s", ms.receive);
    p = liana_plan(MULTI6_RECEIVE0_WS, MULTI6_RECEIVE0_SPK, 0, MULTI6_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE &&
              core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 2 + 5 * 34, 33),
          "an input of it signed by our key, last as written");
    p = liana_plan(SORTED6_RECEIVE0_WS, SORTED6_RECEIVE0_SPK, 0, SORTED6_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_WALLET, "the same keys sorted are not this wallet's input");
    core_multisig_unload();

    CHECK(load("wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*," K4 "/<0;1>/*," K5
               "/<0;1>/*," K1A "/<0;1>/*))") == CORE_ERR_FORMAT,
          "seven keys");
    CHECK(load("wsh(multi(3," K0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT, "multi() above its keys");
    CHECK(load("wsh(multi(2," K0 "/<2;3>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT, "multi() keeps receive 0, change 1");
}

static void or_d_two_keys(void) {
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_SIGS];
    unsigned int n_sigs;
    plan_t p;

    CHECK(load(DECAY) == CORE_OK && ms.n == 6 && ms.primary == 3 && ms.threshold2 == 1 && ms.ours == 0 &&
              ms.ours2 == 3 && !strcmp(ms.receive, DECAY_RECEIVE0) && !strcmp(ms.descriptor, DECAY "#" DECAY_SUM),
          "a decaying 2-of-3 with our xpub on both paths: %s", ms.descriptor);
    p = liana_plan(DECAY_RECEIVE0_WS, DECAY_RECEIVE0_SPK, 0, DECAY_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.n_sign == 1 && r.owner[1] == CORE_OUT_CHANGE,
          "an input of it reviewed, its change recognised");
    CHECK(core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 2 && sigs[0].input == 0 && sigs[1].input == 0 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 2, 33) &&
              !memcmp(sigs[1].pubkey, p.wscripts[0].bytes + 109, 33),
          "signed by our key on each path");
    p = liana_plan(DECAY_RECEIVE0_WS, DECAY_RECEIVE0_SPK, 2, DECAY_CHANGE0_SPK, 3);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[1] == CORE_OUT_CHANGE &&
              core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 2 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 109, 33) &&
              !memcmp(sigs[1].pubkey, p.wscripts[0].bytes + 2, 33),
          "the same when the PSBT names our recovery key, change on 3");
    p.inputs[0].key.path[5] = 1;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NOT_OURS, "our recovery key at another index");

    CHECK(load(SELF) == CORE_OK && ms.ours == 0 && ms.ours2 == 1 && !strcmp(ms.descriptor, SELF "#" SELF_SUM),
          "Liana with our own key for recovery");
    p = liana_plan(SELF_RECEIVE0_WS, SELF_RECEIVE0_SPK, 0, SELF_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 2 &&
              !memcmp(sigs[0].pubkey, p.wscripts[0].bytes + 1, 33) && memcmp(sigs[1].pubkey, sigs[0].pubkey, 33),
          "signed by the pk() key and the pkh() one");

    core_multisig_unload();
    p = liana_plan(DECAY_RECEIVE0_WS, DECAY_RECEIVE0_SPK, 0, DECAY_CHANGE0_SPK, 1);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && core_sign(&p, NULL, sigs, &n_sigs) == CORE_OK && n_sigs == 1,
          "without the wallet, only the key the PSBT names");

    CHECK(load("wsh(or_d(multi(2," K0 "/<0;1>/*," K0 "/<2;3>/*),and_v(v:pkh(" K1 "/<0;1>/*),older(144))))") ==
              CORE_ERR_FORMAT,
          "our xpub twice on one path");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K0 "/<1;2>/*),older(144))))") == CORE_ERR_FORMAT,
          "our xpub on both paths sharing a step");
    CHECK(load("wsh(or_d(pk(" K0 "/<0;1>/*),and_v(v:pkh(" K0 "/<0;1>/*),older(144))))") == CORE_ERR_FORMAT,
          "our xpub on both paths at the same steps");
}

int main(void) {
    uint8_t seed[64], cbor[1024], mainnet_cbor[1024];
    static const char mn[] =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char canonical[CORE_MULTISIG_DESC_MAX], addr[ADDRESS_MAX];
    int n, mainnet_cbor_len = 0;

    pbkdf2_hmac_sha512((const uint8_t *)mn, sizeof(mn) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);
    CHECK(core_init(CORE_MAINNET) && core_load_seed(seed), "load mainnet");

    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "no wallet, no crypto-output");
    CHECK(core_multisig_address(0, 0, addr) == CORE_ERR_WALLET && !addr[0], "no wallet, no address");
    CHECK(core_multisig_find_address(RECEIVE0, strlen(RECEIVE0), 10) == -CORE_ERR_WALLET, "no wallet, nothing found");
    CHECK(load(DESC) == CORE_OK, "a descriptor");
    CHECK(ms.threshold == 2 && ms.n == 3 && ms.ours == 0, "2 of 3, ours first");
    {
        core_facts_t f;
        CHECK(core_facts(&(plan_t){0}, &f) == CORE_OK && f.wallet, "facts say a wallet is registered");
    }
    CHECK(ms.fingerprints[1] == 0x3f635a63 && ms.fingerprints[2] == 0xb8688df1, "the cosigners' fingerprints");
    CHECK(!strcmp(ms.receive, RECEIVE0), "the first receive address is Core's: %s", ms.receive);
    CHECK(!strcmp(ms.descriptor, DESC "#" CHECKSUM), "the descriptor with Core's checksum: %s", ms.descriptor);
    CHECK(core_multisig_address(0, 0, addr) == CORE_OK && !strcmp(addr, RECEIVE0), "receive 0 is load's: %s", addr);
    CHECK(core_multisig_address(1, 0, addr) == CORE_OK && !strcmp(addr, CHANGE0), "change 0 is Core's: %s", addr);
    CHECK(core_multisig_address(2, 0, addr) == CORE_ERR_FORMAT &&
              core_multisig_address(0, 100000, addr) == CORE_ERR_FORMAT,
          "chain 2 and index 100000 refused");
    CHECK(core_multisig_find_address(RECEIVE0, strlen(RECEIVE0), 10) == 0, "receive 0 found");
    CHECK(core_multisig_find_address(CHANGE0, strlen(CHANGE0), 10) == 1 << 20, "change 0 found");
    CHECK(core_multisig_address(1, 7, addr) == CORE_OK &&
              core_multisig_find_address(addr, strlen(addr), 10) == (1 << 20 | 7),
          "change 7 found");
    CHECK(core_multisig_find_address(addr, strlen(addr), 7) == -CORE_ERR_NOT_FOUND, "beyond count, not found");
    CHECK(core_multisig_find_address(UPPER0, strlen(UPPER0), 1) == 0, "upper case, as a QR carries it");
    CHECK(core_multisig_find_address("bc1qEA2GKGESZR7WM66X2EJKGDXM9NHG9462SSZN75ZMKHAZEV0T02VS70KKLL", 62, 1) ==
              -CORE_ERR_FORMAT,
          "mixed case refused");
    CHECK(core_multisig_find_address(LIANA1_RECEIVE0, strlen(LIANA1_RECEIVE0), 10) == -CORE_ERR_NOT_FOUND,
          "another wallet's address, not found");
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
    or_d_multi();
    or_d_two_keys();
    wide();

    core_unload();
    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "unloading the seed unloads the wallet");
    CHECK(load(DESC) == CORE_ERR_NO_SEED, "no seed, no wallet");

    /* Watching needs no seed: the addresses, but no change or inputs, as if no wallet were registered */
    CHECK(core_multisig_watch(DESC, strlen(DESC), &ms) == CORE_OK && ms.ours == 0xff && !strcmp(ms.receive, RECEIVE0) &&
              !strcmp(ms.descriptor, DESC "#" CHECKSUM),
          "watched without a seed: Core's receive address and descriptor");
    CHECK(core_multisig_address(1, 0, addr) == CORE_OK && !strcmp(addr, CHANGE0), "a watched wallet's change 0");
    CHECK(core_multisig_find_address(UPPER0, strlen(UPPER0), 1) == 0, "and its receive 0 found");
    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "but no crypto-output, which says it is ours");
    {
        core_facts_t f;
        CHECK(core_facts(&(plan_t){0}, &f) == CORE_ERR_NO_SEED, "and no review without a seed");
    }
    CHECK(core_load_seed(seed) && core_multisig_address(0, 0, addr) == CORE_ERR_WALLET,
          "loading a seed forgets the watched wallet");
    CHECK(core_multisig_watch(DESC, strlen(DESC), &ms) == CORE_OK && ms.ours == 0xff, "watched with a seed loaded too");
    {
        core_facts_t f;
        CHECK(core_facts(&(plan_t){0}, &f) == CORE_OK && !f.wallet, "facts say no wallet is registered for review");
    }
    CHECK(load(DESC) == CORE_OK && ms.ours == 0 && core_multisig_address(0, 0, addr) == CORE_OK,
          "loading replaces watching");
    core_unload();

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(load(DESC) == CORE_ERR_FORMAT, "a mainnet xpub on testnet");
    CHECK(mainnet_cbor_len > 0 &&
              core_multisig_load_cbor(mainnet_cbor, (size_t)mainnet_cbor_len, &ms) == CORE_ERR_FORMAT,
          "mainnet crypto-output is refused on testnet");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
