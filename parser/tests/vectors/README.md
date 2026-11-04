# The vectors we built ourselves

These PSBTs exercise the cases Bitcoin Core's own `rpc_psbt.json` does not: inputs that belong
to a known key, P2TR and P2SH-P2WPKH alongside P2WPKH, a foreign input, and a `non_witness_utxo`
present or missing.
Each `.psbt` has a `.json` beside it holding the plan the parser is expected to produce.

They are **committed rather than generated**, because generating them needs a Bitcoin library to
build a PSBT with — and a library that builds the expectation is a library whose bugs become the
expectation. Committing them fixes the corpus, so a change in a dependency cannot quietly change
what is being tested.

The seed is BIP39's published all-zero test vector (`abandon` x11 + `about`), fingerprint
`73c5da0a`. There is nothing secret here. The P2WSH cosigners are BIP39's `zoo` x11 + `wrong`,
`legal winner ... yellow` and `letter advice ... above` vectors.

| | |
|---|---|
| `own_p2wpkh_1in` | one P2WPKH input, paying out plus change |
| `own_p2wpkh_2in_nwu` | two P2WPKH inputs, both with their previous transaction |
| `own_p2tr_2in` | two P2TR key-path inputs |
| `own_mixed_nwu` | P2WPKH and P2TR in one transaction |
| `own_p2sh_p2wpkh_1in` | one BIP49 P2SH-P2WPKH input, paying out plus P2SH change |
| `own_mixed_p2sh_nwu` | P2WPKH and P2SH-P2WPKH in one transaction |
| `own_with_p2sh_multisig_input` | one P2WPKH input ours, beside a P2SH multisig whose key and fingerprint are ours too |
| `own_with_foreign_input` | one input ours, one someone else's |
| `own_p2wsh_2of3_1in` | one BIP48 P2WSH 2-of-3 input, paying out plus P2WSH change |
| `own_p2wsh_2of3_cosigned` | the same, with a cosigner's signature already in it |
| `own_mixed_p2wsh_nwu` | P2WPKH and P2WSH 2-of-3 in one transaction |
| `own_with_p2wsh_2of7_input` | one P2WPKH input ours, beside a P2WSH 2-of-7: too many keys for the plan |
| `own_liana_primary_1in` | one Liana input, ours the primary key, recovery after 52596 blocks; paying out plus change |
| `own_liana_recovery_1in` | the same with ours the recovery key on chains 2 and 3, spent once `older(144)` holds |
| `own_or_d_pk_primary_1in` | the same shape with `v:pk` for the recovery key, as Nunchuk writes it, and a time-based `older(4194432)`; ours the primary key |
| `own_or_d_pk_after_recovery_1in` | `v:pk` with `after(1000000)`, ours the recovery key, the locktime at 1000000 |
| `own_or_d_multi_ek_primary_1in` | Keeper's Emergency Key: ours in a 2-of-3 `multi`, the recovery `v:pkh` after block 900000 |
| `own_or_d_multi_recovery_1in` | a 2-of-3 `multi` on each path, ours on the recovery one: a 219-byte witness script, the plan's limit |

## Regenerating them

`tools/gen_vectors.py` still builds them, with [embit](https://github.com/diybitcoinhardware/embit)
as an independent implementation. It is not part of `make test`; run it only to add a case or to
change one deliberately:

```sh
uv run tools/gen_vectors.py tests/rpc_psbt.json tests/vectors
```

Then read the diff before committing it. A change here changes what every test believes.

## What checks them

That these PSBTs mean what the `.json` says is checked twice, and the second time is the one that
matters: `../../tools/check_against_core.mjs` asks **Bitcoin Core** to decode the same files and
requires its answer to match, and requires the signatures `signer.wasm` produces over them to equal
Core's byte for byte.
