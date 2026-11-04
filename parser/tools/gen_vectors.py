# /// script
# dependencies = ["embit"]
# ///
"""Writes test PSBTs and the plan the parser is expected to produce (JSON) to build/vectors/.
Expectations come from how each PSBT was built (which inputs and outputs are ours), not from re-implementing the parser.
Also converts Bitcoin Core's rpc_psbt.json to binary files."""
import base64, hashlib, json, os, sys
from embit import bip32, script
from embit.descriptor import Descriptor
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

MN = " ".join(["abandon"] * 11 + ["about"])  # BIP39 test vector; never use for funds
root = bip32.HDKey.from_seed(hashlib.pbkdf2_hmac("sha512", MN.encode(), b"mnemonic", 2048))
FP = root.my_fingerprint
H = 0x80000000
out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)


def key(path):
    return root.derive(path).key.get_public_key()


def path_list(path):
    return [int(p[:-1]) + H if p.endswith("h") else int(p) for p in path.split("/")[1:]]


# m/45h stands for a P2SH multisig we cosign: our key and fingerprint are in it, but it is not BIP49's
def multisig(path):
    return script.multisig(1, [key(path)])


# BIP48 P2WSH 2-of-3 with two cosigners from BIP39's other published vectors. m/48h/0h/1h/2h holds four keys:
# a witness script too long for the plan, so the input is not one we sign
COSIGNERS = [bip32.HDKey.from_seed(hashlib.pbkdf2_hmac("sha512", m.encode(), b"mnemonic", 2048))
             for m in ("zoo " * 11 + "wrong",
                       "legal winner thank year wave sausage worth useful legal winner thank yellow",
                       "letter advice cage absurd amount doctor acoustic avoid letter advice cage above")]


def cosigner_keys(path):
    n = 3 if path.startswith("m/48h/0h/1h") else 2
    return [c.derive(path).key.get_public_key() for c in COSIGNERS[:n]]


def wsh_script(path):
    return script.Script(script.multisig(2, sorted([key(path)] + cosigner_keys(path), key=lambda k: k.sec())).data)


def spk(path):
    if path.startswith("m/48h"):
        return script.p2wsh(wsh_script(path))
    if path.startswith("m/45h"):
        return script.p2sh(multisig(path))
    if path.startswith("m/86h"):
        return script.p2tr(key(path))
    if path.startswith("m/49h"):
        return script.p2sh(script.p2wpkh(key(path)))
    return script.p2wpkh(key(path))


def prev_tx(target_spk, amount, vout, salt):
    outs = [TransactionOutput(1000 + i, script.Script(b"\x00\x14" + bytes([salt]) * 20)) for i in range(vout)]
    outs.append(TransactionOutput(amount, target_spk))
    return Transaction(vin=[TransactionInput(bytes([salt]) * 32, 0)], vout=outs)


def keypath(path):
    return {"fingerprint": int.from_bytes(FP, "big"), "path": path_list(path)}


def wsh_expected(path):
    return path is not None and path.startswith("m/48h/0h/0h")


def build(name, inputs, outputs, cosigned=False):
    """inputs: (path, or None for a foreign key, amount, vout, nwu). outputs: (path, or None for external, amount)"""
    vin, prevs, exp_in, exp_out = [], [], [], []
    for n, (path, amount, vout, nwu) in enumerate(inputs):
        s = spk(path) if path else script.p2wpkh(key("m/0h/%d" % n))  # stands in for a foreign key (no fingerprint)
        ptx = prev_tx(s, amount, vout, 0x30 + n)
        prevs.append((ptx, vout, s, amount))
        vin.append(TransactionInput(ptx.txid(), vout, sequence=0xFFFFFFFD))
        exp_in.append({"prev_txid": bytes(reversed(ptx.txid())).hex(), "prev_vout": vout, "sequence": 0xFFFFFFFD,
                       "amount": amount, "spk": s.data.hex(),
                       "key": keypath(path) if path and not path.startswith(("m/45h", "m/48h/0h/1h")) else None,
                       "sighash_type": (0 if path.startswith("m/86h") else 1)
                       if path and not path.startswith(("m/45h", "m/48h/0h/1h")) else 0,
                       "wscript": wsh_script(path).data.hex() if wsh_expected(path) else "",
                       "has_prevtx": nwu})
    vout = []
    for n, (path, amount) in enumerate(outputs):
        s = spk(path) if path else script.p2wpkh(key("m/1h/%d" % n))
        vout.append(TransactionOutput(amount, s))
        exp_out.append({"amount": amount, "spk": s.data.hex(),
                        "key": keypath(path) if path else None})
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout))
    for inp, (path, _, _, nwu), (ptx, v, s, amount) in zip(psbt.inputs, inputs, prevs):
        inp.witness_utxo = TransactionOutput(amount, s)
        if nwu:
            inp.non_witness_utxo = ptx
        if path and path.startswith("m/86h"):
            inp.taproot_bip32_derivations[key(path)] = ([], DerivationPath(FP, path_list(path)))
        elif path:
            inp.bip32_derivations[key(path)] = DerivationPath(FP, path_list(path))
        if path and path.startswith("m/49h"):
            inp.redeem_script = script.p2wpkh(key(path))
        if path and path.startswith("m/45h"):
            inp.redeem_script = multisig(path)
        if path and path.startswith("m/48h"):
            inp.witness_script = wsh_script(path)
            for c, k in zip(COSIGNERS, cosigner_keys(path)):
                inp.bip32_derivations[k] = DerivationPath(c.my_fingerprint, path_list(path))
    if cosigned:  # the first cosigner has signed already
        psbt.sign_with(COSIGNERS[0])
    for o, (path, _) in zip(psbt.outputs, outputs):
        if path and path.startswith("m/86h"):
            o.taproot_bip32_derivations[key(path)] = ([], DerivationPath(FP, path_list(path)))
        elif path:
            o.bip32_derivations[key(path)] = DerivationPath(FP, path_list(path))
        if path and path.startswith("m/49h"):
            o.redeem_script = script.p2wpkh(key(path))
        if path and path.startswith("m/48h"):
            o.witness_script = wsh_script(path)
            for c, k in zip(COSIGNERS, cosigner_keys(path)):
                o.bip32_derivations[k] = DerivationPath(c.my_fingerprint, path_list(path))
    open(os.path.join(out_dir, name + ".psbt"), "wb").write(psbt.serialize())
    expected = {"fingerprint": int.from_bytes(FP, "big"), "tx_version": 2, "locktime": 0,
                "inputs": exp_in, "outputs": exp_out,
                "pubkeys": [key(p).sec().hex() if p else None for p, _, _, _ in inputs]}
    json.dump(expected, open(os.path.join(out_dir, name + ".json"), "w"), indent=1)


A, T, S = "m/84h/0h/0h", "m/86h/0h/0h", "m/49h/0h/0h"
build("own_p2wpkh_1in", [(A + "/0/0", 100000, 0, False)], [(None, 60000), (A + "/1/0", 39000)])
build("own_p2wpkh_2in_nwu", [(A + "/0/0", 100000, 1, True), (A + "/0/1", 50000, 0, True)],
      [(None, 60000), (A + "/1/0", 89000)])
build("own_p2tr_2in", [(T + "/0/0", 70000, 0, False), (T + "/0/1", 70000, 2, False)],
      [(None, 100000), (T + "/1/0", 39000)])
build("own_mixed_nwu", [(A + "/0/0", 100000, 0, True), (T + "/0/0", 70000, 1, True)],
      [(None, 100000), (A + "/0/5", 20000), (T + "/1/0", 49000)])
build("own_p2sh_p2wpkh_1in", [(S + "/0/0", 100000, 0, False)], [(None, 60000), (S + "/1/0", 39000)])
build("own_mixed_p2sh_nwu", [(A + "/0/0", 100000, 0, True), (S + "/0/1", 50000, 1, True)],
      [(None, 100000), (S + "/1/0", 49000)])
build("own_with_p2sh_multisig_input", [(A + "/0/0", 100000, 0, True), ("m/45h/0/0/0", 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])
# P2WSH change carries our key; the signer calls it change only once a registered wallet gives the cosigners'
W = "m/48h/0h/0h/2h"
build("own_p2wsh_2of3_1in", [(W + "/0/0", 100000, 0, False)], [(None, 60000), (W + "/1/0", 39000)])
build("own_p2wsh_2of3_cosigned", [(W + "/0/1", 100000, 1, True)], [(None, 60000), (W + "/1/1", 39000)],
      cosigned=True)
build("own_mixed_p2wsh_nwu", [(A + "/0/0", 100000, 0, True), (W + "/0/2", 50000, 0, True)],
      [(None, 100000), (A + "/1/0", 49000)])
build("own_with_p2wsh_2of4_input", [(A + "/0/0", 100000, 0, True), ("m/48h/0h/1h/2h/0/0", 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])
build("own_with_foreign_input", [(A + "/0/0", 100000, 0, True), (None, 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])


# or_d as Liana writes it, or with v:pk / after() as Nunchuk can: ours the primary key on chains 0 and 1, or the
# recovery key on 2 and 3 as Liana numbers a key's second use. The recovery spend waits on its sequence or locktime
def build_or_d(name, ours_primary, lock, recovery="pkh", timelock="older"):
    xpub = lambda k: "[%s%s]%s" % (k.my_fingerprint.hex(), W[1:], k.derive(W).to_public().to_base58())
    chains = (0, 1) if ours_primary else (2, 3)

    def wallet(chain):
        a, b = "%s/%d/*" % (xpub(root), chain), "%s/%d/*" % (xpub(COSIGNERS[0]), chain - chains[0])
        primary, b_key = (a, b) if ours_primary else (b, a)
        return Descriptor.from_string("wsh(or_d(pk(%s),and_v(v:%s(%s),%s(%d))))" % (primary, recovery, b_key, timelock, lock)).derive(0)

    def fill(o, chain):
        o.witness_script = wallet(chain).witness_script()
        o.bip32_derivations[key("%s/%d/0" % (W, chain))] = DerivationPath(FP, path_list("%s/%d/0" % (W, chain)))
        c = COSIGNERS[0].derive("%s/%d/0" % (W, chain - chains[0]))
        o.bip32_derivations[c.key.get_public_key()] = DerivationPath(COSIGNERS[0].my_fingerprint,
                                                                     path_list("%s/%d/0" % (W, chain - chains[0])))

    seq = lock if timelock == "older" and not ours_primary else 0xFFFFFFFD
    locktime = lock if timelock == "after" and not ours_primary else 0
    s_in, s_change = wallet(chains[0]).script_pubkey(), wallet(chains[1]).script_pubkey()
    ptx = prev_tx(s_in, 100000, 0, 0x40)
    pay = script.p2wpkh(key("m/1h/0"))
    psbt = PSBT(Transaction(version=2, locktime=locktime, vin=[TransactionInput(ptx.txid(), 0, sequence=seq)],
                            vout=[TransactionOutput(60000, pay), TransactionOutput(39000, s_change)]))
    psbt.inputs[0].witness_utxo = TransactionOutput(100000, s_in)
    fill(psbt.inputs[0], chains[0])
    fill(psbt.outputs[1], chains[1])
    open(os.path.join(out_dir, name + ".psbt"), "wb").write(psbt.serialize())
    ours = "%s/%d/0" % (W, chains[0])
    expected = {"fingerprint": int.from_bytes(FP, "big"), "tx_version": 2, "locktime": locktime,
                "inputs": [{"prev_txid": bytes(reversed(ptx.txid())).hex(), "prev_vout": 0, "sequence": seq,
                            "amount": 100000, "spk": s_in.data.hex(), "key": keypath(ours), "sighash_type": 1,
                            "wscript": wallet(chains[0]).witness_script().data.hex(), "has_prevtx": False}],
                "outputs": [{"amount": 60000, "spk": pay.data.hex(), "key": None},
                            {"amount": 39000, "spk": s_change.data.hex(), "key": keypath("%s/%d/0" % (W, chains[1]))}],
                "pubkeys": [key(ours).sec().hex()]}
    json.dump(expected, open(os.path.join(out_dir, name + ".json"), "w"), indent=1)


build_or_d("own_liana_primary_1in", True, 52596)
build_or_d("own_liana_recovery_1in", False, 144)
build_or_d("own_or_d_pk_primary_1in", True, 4194432, "pk")
build_or_d("own_or_d_pk_after_recovery_1in", False, 1000000, "pk", "after")

vectors = json.load(open(sys.argv[1]))
for kind in ("invalid", "invalid_with_msg", "valid"):
    for n, v in enumerate(vectors[kind]):
        b64 = v if isinstance(v, str) else v[0]
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception:
            continue  # the base64 itself is broken; the parser takes binary, so these are out of scope
        open(os.path.join(out_dir, "rpc_%s_%02d.psbt" % (kind, n)), "wb").write(raw)
