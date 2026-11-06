#include "multisig.h"
#include <string.h>
#include "bip32.h"
#include "hash.h"

#define H 0x80000000u

static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

typedef struct {
    const char *s;
    size_t n, i;
} cur_t;

static int eat(cur_t *c, const char *lit) {
    size_t k = strlen(lit);
    if (c->n - c->i < k || memcmp(c->s + c->i, lit, k)) return 0;
    c->i += k;
    return 1;
}

/* Decimal below 2^31, without leading zeros */
static int number(cur_t *c, uint32_t *v) {
    size_t start = c->i;
    uint64_t x = 0;
    while (c->i < c->n && c->s[c->i] >= '0' && c->s[c->i] <= '9') {
        x = x * 10 + (uint64_t)(c->s[c->i++] - '0');
        if (x >= H) return 0;
    }
    *v = (uint32_t)x;
    return c->i > start && (c->i - start == 1 || c->s[start] != '0');
}

static int hex_fp(cur_t *c, uint32_t *fp) {
    *fp = 0;
    for (int k = 0; k < 8; k++, c->i++) {
        char ch = c->i < c->n ? c->s[c->i] : 0;
        int d = ch >= '0' && ch <= '9'   ? ch - '0'
                : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
                : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10
                                         : -1;
        if (d < 0) return 0;
        *fp = *fp << 4 | (uint32_t)d;
    }
    return 1;
}

/* /a'/b'/... with h, H or ' marking each step, every one of them hardened */
static int origin(cur_t *c, ms_key_t *k) {
    k->depth = 0;
    while (eat(c, "/")) {
        if (k->depth == MS_MAX_DEPTH || !number(c, &k->path[k->depth])) return 0;
        if (!eat(c, "h") && !eat(c, "H") && !eat(c, "'")) return 0;
        k->path[k->depth++] |= H;
    }
    return k->depth > 0;
}

static uint32_t be32(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

/* The xpub has to sit where its origin says: same depth, same last step. SLIP-132's Zpub / Vpub name the same
 * key as xpub / tpub, and SeedSigner and Krux show them */
static int xpub(cur_t *c, int testnet, ms_key_t *k) {
    size_t start = c->i;
    uint32_t v;
    secp256k1_pubkey pk;
    while (c->i < c->n && ((c->s[c->i] >= '0' && c->s[c->i] <= '9') || (c->s[c->i] >= 'A' && c->s[c->i] <= 'Z') ||
                           (c->s[c->i] >= 'a' && c->s[c->i] <= 'z')))
        c->i++;
    if (!base58check_decode(c->s + start, c->i - start, k->ser, sizeof(k->ser))) return 0;
    v = be32(k->ser);
    if (testnet ? v != 0x043587cfu && v != 0x02575483u : v != 0x0488b21eu && v != 0x02aa7ed3u) return 0;
    return k->ser[4] == k->depth && be32(k->ser + 9) == k->path[k->depth - 1] &&
           secp256k1_ec_pubkey_parse(secp256k1_context_static, &pk, k->ser + 45, 33);
}

/* [fp/a'/b'/...]xpub, then its children: <a;b>, ** as BSMS writes it, or 0 with change on 1 by convention */
static int key_expr(cur_t *c, int testnet, ms_key_t *k) {
    if (!eat(c, "[") || !hex_fp(c, &k->fingerprint) || !origin(c, k) || !eat(c, "]") || !xpub(c, testnet, k)) return 0;
    k->child[0] = 0, k->child[1] = 1;
    if (eat(c, "/**") || eat(c, "/0/*")) return 1;
    return eat(c, "/<") && number(c, &k->child[0]) && eat(c, ";") && number(c, &k->child[1]) && eat(c, ">/*") &&
           k->child[0] != k->child[1];
}

static uint64_t desc_polymod(uint64_t c, unsigned int v) {
    uint64_t c0 = c >> 35;
    c = ((c & 0x7ffffffffull) << 5) ^ v;
    if (c0 & 1) c ^= 0xf5dee51989ull;
    if (c0 & 2) c ^= 0xa9fdca3312ull;
    if (c0 & 4) c ^= 0x1bab10e32dull;
    if (c0 & 8) c ^= 0x3706b1677aull;
    if (c0 & 16) c ^= 0x644d626ffdull;
    return c;
}

/* BIP380's descriptor checksum */
static int desc_checksum(const char *s, size_t n, char out[9]) {
    static const char IN[] =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    uint64_t c = 1;
    unsigned int cls = 0, count = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = s[i] ? strchr(IN, s[i]) : NULL;
        if (!p) return 0;
        c = desc_polymod(c, (unsigned int)(p - IN) & 31);
        cls = cls * 3 + (unsigned int)(p - IN) / 32;
        if (++count == 3) c = desc_polymod(c, cls), cls = count = 0;
    }
    if (count) c = desc_polymod(c, cls);
    for (int j = 0; j < 8; j++) c = desc_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; j++) out[j] = B32[(c >> (5 * (7 - j))) & 31];
    out[8] = 0;
    return 1;
}

/* pk(KEY), pkh(KEY) where pkh is not NULL, or multi(m,KEY,...) of two or three keys, appended to w's keys.
 * Returns its threshold, 1 for a single key, or 0 */
static unsigned int side(cur_t *c, int testnet, ms_wallet_t *w, int *pkh) {
    unsigned int start = w->n;
    uint32_t m = 1;
    if (eat(c, "pk(") || (pkh && (*pkh = eat(c, "pkh(")))) {
        if (!key_expr(c, testnet, &w->keys[w->n++])) return 0;
    } else {
        if (!eat(c, "multi(") || !number(c, &m)) return 0;
        while (eat(c, ","))
            if (w->n - start == MS_MAX_SIDE || !key_expr(c, testnet, &w->keys[w->n++])) return 0;
        if (w->n - start < 2 || m < 1 || m > w->n - start) return 0;
    }
    return eat(c, ")") ? m : 0;
}

/* wsh(sortedmulti(k,KEY,...)), wsh(multi(k,KEY,...)) or wsh(or_d(X,and_v(v:Y,older(n)))) as ms_wallet_t describes it,
 * and if there is one, a checksum that has to hold */
static int descriptor(cur_t *c, int testnet, ms_wallet_t *w) {
    size_t start = c->i;
    uint32_t k;
    unsigned int m, m2;
    int pkh = 0;
    char sum[9];
    if (eat(c, "wsh(or_d(")) {
        if (!(m = side(c, testnet, w, NULL)) || !eat(c, ",and_v(v:")) return 0;
        w->primary = w->n;
        if (!(m2 = side(c, testnet, w, &pkh)) || !eat(c, ",")) return 0;
        w->kind = MS_OR_D | (w->n - w->primary == 1 && !pkh ? MS_OR_D_PK : 0);
        if (eat(c, "after(")) w->kind |= MS_OR_D_AFTER;
        else if (!eat(c, "older(")) return 0;
        if (!number(c, &k) || !eat(c, "))))") || k < 1) return 0;
        w->threshold = (uint8_t)m, w->threshold2 = (uint8_t)m2, w->lock = k;
    } else {
        if (!eat(c, "wsh(sortedmulti(")) {
            if (!eat(c, "wsh(multi(")) return 0;
            w->kind = MS_MULTI;
        }
        if (!number(c, &k)) return 0;
        for (w->n = 0; eat(c, ",");) {
            ms_key_t *key = &w->keys[w->n];
            if (w->n == MS_MAX_KEYS || !key_expr(c, testnet, key) || key->child[0] != 0 || key->child[1] != 1) return 0;
            w->n++;
        }
        if (!eat(c, "))") || k < 1 || k > w->n) return 0;
        w->threshold = (uint8_t)k;
    }
    if (!eat(c, "#")) return 1;
    if (!desc_checksum(c->s + start, c->i - 1 - start, sum) || c->n - c->i < 8 || memcmp(c->s + c->i, sum, 8)) return 0;
    c->i += 8;
    return 1;
}

/* The next line, without its line ending or the spaces around it */
static int line(cur_t *c, cur_t *l) {
    size_t a, b;
    if (c->i >= c->n) return 0;
    a = c->i;
    while (c->i < c->n && c->s[c->i] != '\n') c->i++;
    b = c->i;
    if (c->i < c->n) c->i++;
    while (a < b && (c->s[a] == ' ' || c->s[a] == '\t')) a++;
    while (b > a && (c->s[b - 1] == ' ' || c->s[b - 1] == '\t' || c->s[b - 1] == '\r')) b--;
    l->s = c->s + a, l->n = b - a, l->i = 0;
    return 1;
}

static int label(cur_t *l, const char *name) {
    size_t k = strlen(name);
    if (l->n < k + 1 || l->s[k] != ':') return 0;
    for (size_t i = 0; i < k; i++)
        if ((l->s[i] | 0x20) != name[i]) return 0;
    for (l->i = k + 1; l->i < l->n && l->s[l->i] == ' ';) l->i++;
    return 1;
}

/* BIP129: the header, the descriptor, the path restrictions and the first receive address */
static int bsms(cur_t *c, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]) {
    cur_t l;
    if (!line(c, &l) || !eat(&l, "BSMS 1.0") || l.i != l.n) return 0;
    if (!line(c, &l) || !descriptor(&l, testnet, w) || l.i != l.n) return 0;
    if (!line(c, &l) || (!eat(&l, "/0/*,/1/*") && !eat(&l, "No path restrictions")) || l.i != l.n) return 0;
    if (!line(c, &l) || l.n == 0 || l.n >= ADDRESS_MAX) return 0;
    for (size_t i = 0; i < l.n; i++) address[i] = l.s[i] >= 'A' && l.s[i] <= 'Z' ? (char)(l.s[i] | 0x20) : l.s[i];
    address[l.n] = 0;
    while (line(c, &l))
        if (l.n) return 0;
    return 1;
}

/* Coldcard's setup file, which Sparrow, BlueWallet and Nunchuk also write: Name, Policy: M of N, Derivation
 * (for the keys after it), Format: P2WSH, then FINGERPRINT: xpub lines. # starts a comment */
static int setup_file(cur_t *c, int testnet, ms_wallet_t *w) {
    cur_t l;
    ms_key_t at = {0};
    uint32_t m = 0, n = 0;
    int p2wsh = 0;
    w->n = 0;
    while (line(c, &l)) {
        if (!l.n || l.s[0] == '#' || label(&l, "name")) continue;
        if (label(&l, "policy")) {
            if (!number(&l, &m) || (!eat(&l, " of ") && !eat(&l, "/")) || !number(&l, &n) || l.i != l.n) return 0;
        } else if (label(&l, "derivation")) {
            if (!eat(&l, "m") || !origin(&l, &at) || l.i != l.n) return 0;
        } else if (label(&l, "format")) {
            if (l.n - l.i != 5 || memcmp(l.s + l.i, "P2WSH", 5)) return 0;
            p2wsh = 1;
        } else {
            ms_key_t *k = &w->keys[w->n];
            if (w->n == MS_MAX_KEYS || !at.depth || !hex_fp(&l, &k->fingerprint) || !eat(&l, ":")) return 0;
            while (eat(&l, " "));
            k->depth = at.depth;
            k->child[1] = 1;
            memcpy(k->path, at.path, sizeof(at.path));
            if (!xpub(&l, testnet, k) || l.i != l.n) return 0;
            w->n++;
        }
    }
    w->threshold = (uint8_t)m;
    return p2wsh && n == w->n && m >= 1 && m <= n;
}

/* Keys i > j differ, or are one xpub on both paths of an or_d under other steps, as a reused signer is */
static int distinct(const ms_wallet_t *w, unsigned int i, unsigned int j) {
    const ms_key_t *a = &w->keys[i], *b = &w->keys[j];
    return memcmp(a->ser + 45, b->ser + 45, 33) ||
           ((w->kind & MS_OR_D) && j < w->primary && i >= w->primary && a->child[0] != b->child[0] &&
            a->child[0] != b->child[1] && a->child[1] != b->child[0] && a->child[1] != b->child[1]);
}

int ms_parse(const char *s, size_t len, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]) {
    cur_t c = {s, len, 0};
    int ok;
    memset(w, 0, sizeof(*w));
    address[0] = 0;
    while (c.n && (s[c.n - 1] == '\n' || s[c.n - 1] == '\r' || s[c.n - 1] == ' ')) c.n--;
    if (c.n >= 8 && !memcmp(s, "BSMS 1.0", 8)) ok = bsms(&c, testnet, w, address);
    else if (c.n >= 4 && !memcmp(s, "wsh(", 4)) ok = descriptor(&c, testnet, w) && c.i == c.n;
    else ok = setup_file(&c, testnet, w);
    for (unsigned int i = 0; ok && i < w->n; i++)
        for (unsigned int j = 0; j < i; j++) ok &= distinct(w, i, j);
    if (!ok) memset(w, 0, sizeof(*w)), address[0] = 0;
    return ok;
}

size_t ms_scriptnum(uint32_t n, uint8_t out[5]) {
    size_t len = 1;
    if (n <= 16) return out[0] = (uint8_t)(0x50 + n), 1;
    for (uint32_t v = n; v; v >>= 8) out[len++] = (uint8_t)v;
    if (out[len - 1] & 0x80) out[len++] = 0; /* the top bit would make it negative */
    out[0] = (uint8_t)(len - 1);
    return len;
}

/* pk(K) as <K> CHECKSIG, pkh(K) as DUP HASH160 <HASH160(K)> EQUALVERIFY CHECKSIG, multi(m,...) as m <K>... n
 * CHECKMULTISIG, each with VERIFY if asked. Returns the bytes written */
static size_t put_check(uint8_t *s, unsigned int m, unsigned int n, const uint8_t (*k)[33], int verify, int pkh) {
    size_t o = 0;
    if (pkh) {
        s[o++] = 0x76, s[o++] = 0xa9, s[o++] = 0x14;
        hash160(k[0], 33, s + o), o += 20;
        s[o++] = 0x88;
    }
    if (n > 1) s[o++] = (uint8_t)(0x50 + m);
    for (unsigned int i = 0; i < n && !pkh; i++) {
        s[o++] = 33;
        memcpy(s + o, k[i], 33), o += 33;
    }
    if (n > 1) s[o++] = (uint8_t)(0x50 + n);
    s[o++] = (uint8_t)((n > 1 ? 0xae : 0xac) + verify);
    return o;
}

/* X IFDUP NOTIF Y <n> CSV or CLTV ENDIF, Y with VERIFY */
static void or_d_wscript(const ms_wallet_t *w, const uint8_t (*k)[33], plan_wscript_t *out) {
    unsigned int n2 = w->n - w->primary;
    uint8_t *s = out->bytes;
    size_t o = put_check(s, w->threshold, w->primary, k, 0, 0);
    s[o++] = 0x73, s[o++] = 0x64;
    o += put_check(s + o, w->threshold2, n2, k + w->primary, 1, n2 == 1 && !(w->kind & MS_OR_D_PK));
    o += ms_scriptnum(w->lock, s + o);
    s[o++] = w->kind & MS_OR_D_AFTER ? 0xb1 : 0xb2, s[o++] = 0x68;
    out->len = (uint16_t)o;
}

int ms_wscript(const ms_wallet_t *w, uint32_t chain, uint32_t index, plan_wscript_t *out) {
    uint8_t keys[MS_MAX_KEYS][33], cc[32], mid[33], t[33];
    memset(out, 0, sizeof(*out));
    for (unsigned int i = 0; i < w->n; i++) {
        const ms_key_t *k = &w->keys[i];
        if (!bip32_pub_child(k->ser + 45, k->ser + 13, k->child[chain], mid, cc) ||
            !bip32_pub_child(mid, cc, index, keys[i], cc))
            return 0;
        for (unsigned int j = i; w->kind == MS_SORTEDMULTI && j > 0 && memcmp(keys[j - 1], keys[j], 33) > 0; j--) {
            memcpy(t, keys[j], 33), memcpy(keys[j], keys[j - 1], 33), memcpy(keys[j - 1], t, 33);
        }
    }
    if (w->kind & MS_OR_D) return or_d_wscript(w, (const uint8_t (*)[33])keys, out), 1;
    out->bytes[out->len++] = (uint8_t)(0x50 + w->threshold);
    for (unsigned int i = 0; i < w->n; i++) {
        out->bytes[out->len++] = 33;
        memcpy(out->bytes + out->len, keys[i], 33);
        out->len += 33;
    }
    out->bytes[out->len++] = (uint8_t)(0x50 + w->n);
    out->bytes[out->len++] = 0xae;
    return 1;
}

static size_t put(char *out, size_t o, const char *s) {
    size_t n = strlen(s);
    if (o + n >= MS_DESC_MAX) return MS_DESC_MAX;
    memcpy(out + o, s, n);
    out[o + n] = 0;
    return o + n;
}

static void decimal(uint32_t v, char out[11]) {
    char t[10];
    size_t n = 0, o = 0;
    do t[n++] = (char)('0' + v % 10);
    while (v /= 10);
    while (n) out[o++] = t[--n];
    out[o] = 0;
}

/* A key as [fp/a'h/...]xpub/<a;b> followed by its wildcard */
static size_t put_key(char *out, size_t o, const ms_key_t *k, int testnet) {
    char num[11], x[BASE58CHECK_MAX_OUT];
    uint8_t ser[78];
    o = put(out, o, "[");
    for (int d = 0; d < 8; d++) num[d] = "0123456789abcdef"[k->fingerprint >> (28 - 4 * d) & 15];
    num[8] = 0;
    o = put(out, o, num);
    for (unsigned int d = 0; d < k->depth; d++) {
        decimal(k->path[d] & ~H, num);
        o = put(out, o, "/");
        o = put(out, o, num);
        o = put(out, o, "h");
    }
    o = put(out, o, "]");
    memcpy(ser, k->ser, sizeof(ser));
    memcpy(ser, testnet ? "\x04\x35\x87\xcf" : "\x04\x88\xb2\x1e", 4);
    base58check_data(ser, sizeof(ser), x);
    o = put(out, o, x);
    for (int c = 0; c < 2; c++) {
        decimal(k->child[c], num);
        o = put(out, o, c ? ";" : "/<");
        o = put(out, o, num);
    }
    return put(out, o, ">/*");
}

/* keys [from, to) as pk(), pkh() or multi(m,...) */
static size_t put_side(char *out, size_t o, const ms_wallet_t *w, unsigned int from, unsigned int to, unsigned int m,
                       int pkh, int testnet) {
    char num[11];
    if (to - from == 1) return put(out, put_key(out, put(out, o, pkh ? "pkh(" : "pk("), &w->keys[from], testnet), ")");
    decimal(m, num);
    o = put(out, put(out, o, "multi("), num);
    for (unsigned int i = from; i < to; i++) o = put_key(out, put(out, o, ","), &w->keys[i], testnet);
    return put(out, o, ")");
}

size_t ms_descriptor(const ms_wallet_t *w, int testnet, char out[MS_DESC_MAX]) {
    char num[11];
    size_t o;
    if (w->kind & MS_OR_D) {
        o = put_side(out, put(out, 0, "wsh(or_d("), w, 0, w->primary, w->threshold, 0, testnet);
        o = put(out, o, ",and_v(v:");
        o = put_side(out, o, w, w->primary, w->n, w->threshold2, !(w->kind & MS_OR_D_PK), testnet);
        o = put(out, o, w->kind & MS_OR_D_AFTER ? ",after(" : ",older(");
        decimal(w->lock, num);
        o = put(out, o, num);
        o = put(out, o, "))))");
    } else {
        o = put(out, 0, w->kind == MS_MULTI ? "wsh(multi(" : "wsh(sortedmulti(");
        decimal(w->threshold, num);
        o = put(out, o, num);
        for (unsigned int i = 0; i < w->n; i++) o = put_key(out, put(out, o, ","), &w->keys[i], testnet);
        o = put(out, o, "))");
    }
    if (o + 9 >= MS_DESC_MAX || !desc_checksum(out, o, num)) return 0;
    out[o++] = '#';
    memcpy(out + o, num, 9);
    return o + 8;
}
