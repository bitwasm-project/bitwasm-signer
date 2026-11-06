// Spends or_d wallets and a 15-key multisig on regtest with signer.wasm's signature, to show it satisfies the script and not only
// matches Core's bytes. Core is given the cosigners' keys, never ours: descriptorprocesspsbt fills the PSBT,
// parser.wasm and signer.wasm add our signature, Core adds the cosigners' and finalizes. Each case is tried once before its
// timelock, where it has to be refused, and once after, where it has to be mined.
//
//   node tools/check_spend_on_regtest.mjs "bitcoin-cli -datadir=... -regtest" <parser.wasm> <signer.wasm>
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Signer } from "../signer/hosts/js/signer.mjs";

const [cliSpec, parserPath, signerPath] = process.argv.slice(2);
const CLI = cliSpec.split(/\s+/);
const cli = (...args) => execFileSync(CLI[0], [...CLI.slice(1), ...args], { encoding: "utf8" }).trim();
const json = (...args) => JSON.parse(cli(...args));
const hex = (b) => Buffer.from(b).toString("hex");

const MNEMONIC = "abandon ".repeat(11) + "about";
const OURS = "[73c5da0a/48h/0h/0h/2h]tprv8hRqYMHqbXZkDN5eTQCeeUqJMd8BtX7fPGBofh6N6fiwNTNYjPE9HP4TdVMX8Tud62RaiqNchAYQnCaa4nHkoLBZmQ8xHEufrZqqmCLPspf";
// BIP39's "zoo ... wrong", "legal winner ... yellow" and "letter advice ... above", at accounts 0 and 1
const [C0, C0A, C1, C1A, C2] = [
  "[3f635a63/48h/0h/0h/2h]tprv8iy9adA2cnwqBLRDrxGwkBvd1EM4FwmtzbgGK9nvnaxJrz7QgTH1Y5fwdKCx8cqHhwFWs7aaduiQPC9wp8h6pr2DQUxQP8efkQv2cBtJ2dj",
  "[3f635a63/48h/0h/1h/2h]tprv8i2jHB3v8GFGmgJ8vX2o865VpCg8M25iXZxBWjrtZoNpjfFdHkTej1rxEJ6shSKJ3urpsbgQZ2ufcDmgCpaFpNfpXRmqpzrb2v5Ejr3w1zE",
  "[b8688df1/48h/0h/0h/2h]tprv8j6ZwwmiGKQp8umcRv7EfAVAgss2BsqhqoXJa8P9DoFv78HWTvVVBv7JhfB17aCmu8W2hJebyFH2Y8XUnVhoehpowpnUTFUBCYScZh5xXCu",
  "[b8688df1/48h/0h/1h/2h]tprv8hqwZ88DadzdHutXRukFN39GZRMstZcWMFcW8HSFz3ikES5EQ8XRdNPn3mJr3PGzutCmXVpuoe9ep8vzY7fjx5QZKxnuWbpusGEBRLQSh4s",
  "[28645006/48h/0h/0h/2h]tprv8hTpZCXssDTKo72fFyLNBfHdPz3oSChVDbCFXLnoeFv6uqv7apPsEMdxeUd7KbZFvMeeX4Eowjy26sWjd7XeVNa1UA3M3BzzGZNrfroyR6L",
];
// Nine more at m/48'/0'/0'/2', from BIP39's test vectors, for 15 keys
const MORE = [
  "[b760aecd/48h/0h/0h/2h]tprv8j38c5WaDmndJtTL95zLhEkPBLsWQdenijQVBuXMXBmdK2t9S3M5XwFwtTGT297u74DVbBTNGWDdnBZBi9tzgb8RjgRZtJh5XFr51GrsMeW",
  "[61796c57/48h/0h/0h/2h]tprv8ibFX8K1neaYVjQyUer4esutxwnG3CY2apxkeXueYYjQoBMuuyVSJMhduBkqcRZW7bxfZG4vXNwemar9v2qZZv1VRxudFmoriKXwZ6gt6TG",
  "[8a682d68/48h/0h/0h/2h]tprv8ijH15VfS7yirqB8sFhxhJiVTCGwXbdktqsLLopWhRvWa4b7aCH6bRJyZ4KKUzTp9YcHHh5aCtdD4VhRwKo4EGqDckfrjrcgKhyebE5TaWc",
  "[dd1fad4d/48h/0h/0h/2h]tprv8iMVyqbjxMFpkVwTaJKsR6bgTgLampoQZW8X5wM4jBNZqsk8g6g6Tc8qQ9vjguqqTxRwC1DwpvpN2QumVBMV83AefGRV36dTzDNavzLq4de",
  "[bc2b7c36/48h/0h/0h/2h]tprv8hcuZfSnLWyFeUSZnxF4hMrk1Jb9NdehhPs2kPGPNHdXznVstBbg7vvNS5qsHGJLzJGwt6mgGrxb8MTnf9uLsDjzYV1RySUtsgrRaf5Xu1e",
  "[f57f296d/48h/0h/0h/2h]tprv8j2ctQa3c215KHaAjufxKjYgbHLMrobYGkmZYSeNBhZfKtyUwLWfhhDQHQYZojZh8LCZQfH7SnST6KNrhhzzpywoiMEM6NSqB4vySyKSAbx",
  "[86d722c6/48h/0h/0h/2h]tprv8hEHXsDnD7kZPA8XLkRydKoxvoWEt25mYzwUosjJJN7FPZSkZzByrEvWv3KyNx86g2zeQFZsB7LrwyC75E2JT59BXLbAaGk4GbbUEkFBn89",
  "[5c9e228d/48h/0h/0h/2h]tprv8iMrfZQNNqF9S7UCaZJf4uM9w9bL8b4hPxsZxNHcdzwRWUhmKh61ybUY1LEkJHEBPZePT7LDtqfAYDPfZFjEjN93WpXr8HBfsn9EbLvYP7V",
  "[5436d724/48h/0h/0h/2h]tprv8hnjdQCwuLZyZ1K6HkbvjVXm632pQW5a4T5Wtw1pU2tGPRU1FbeTWxR948RBbw7UPhqyjwyCpeLQbdRg13HnPQk9WwDxKcK3hRKkuyXQ3KK",
];
const pub = (k) => json("getdescriptorinfo", `pk(${k}/0/*)`).descriptor.replace(/^pk\((.*)\/0\/\*\)#.*$/, "$1");
const withChecksum = (d) => `${d}#${json("getdescriptorinfo", d).checksum}`;

// [name, policy with {o} for ours, {o2} ours again on 2 and 3, {c0}... the cosigners, the cosigners Core signs for,
// the timelock]. The recovery cases give Core no key on the primary path, so only the recovery path can spend
const CASES = [
  ["Liana, ours the primary key", "or_d(pk({o}),and_v(v:pkh({c0}),older(10)))", [], null],
  ["Liana, ours the recovery key", "or_d(pk({c0}),and_v(v:pkh({o}),older(10)))", [], { older: 10 }],
  ["v:pk with after(), ours the recovery key", "or_d(pk({c0}),and_v(v:pk({o}),after({h})))", [], { after: 5 }],
  ["Keeper's Emergency Key, ours in the 2-of-3", "or_d(multi(2,{o},{c0},{c1}),and_v(v:pkh({c2}),after({h})))",
   ["c0"], null],
  ["Keeper's Emergency Key, ours the Emergency Key", "or_d(multi(2,{c0},{c1},{c2}),and_v(v:pkh({o}),after({h})))",
   [], { after: 5 }],
  ["two 2-of-3s at 219 bytes, ours on the recovery path",
   "or_d(multi(2,{c0},{c1},{c2}),and_v(v:multi(2,{o},{c0a},{c1a}),after({h})))", ["c0a"], { after: 5 }],
  // A reused signer: registered, it signs with both keys, and the recovery path needs the second one
  ["ours on both paths, spent on the primary path", "or_d(multi(2,{o},{c0},{c1}),and_v(v:multi(2,{o2},{c0a},{c1a}),older(10)))",
   ["c0"], null],
  // 513 bytes of witness script, whose scriptCode takes a three-byte compact size
  ["an 8-of-15 sortedmulti", `sortedmulti(8,{o},{c0},{c0a},{c1},{c1a},{c2},${MORE.map((_, i) => `{m${i}}`).join(",")})`,
   ["c0", "c0a", "c1", "c1a", "c2", "m0", "m1"], null],
  ["ours on both paths, spent on the recovery path", "or_d(multi(2,{o},{c0},{c1}),and_v(v:multi(2,{o2},{c0a},{c1a}),older(10)))",
   ["c0a"], { older: 10 }],
];
const COSIGNERS = { c0: C0, c0a: C0A, c1: C1, c1a: C1A, c2: C2, ...Object.fromEntries(MORE.map((k, i) => [`m${i}`, k])) };

const P = (await WebAssembly.instantiate(readFileSync(parserPath), {})).instance.exports;
const signerWasm = readFileSync(signerPath);
const pin = { sha256: createHash("sha256").update(signerWasm).digest("hex") };

/** parser.wasm and signer.wasm sign the PSBT for our keys, as a host would, with the wallet registered when one is
 *  given; the signed PSBT comes back */
async function signHere(psbt, registered) {
  const mem = () => new Uint8Array(P.memory.buffer);
  mem().set(psbt, P.parser_input());
  const rc = P.parser_parse(psbt.length, 0x73c5da0a);
  if (rc !== 0) throw new Error(`parser_parse: ${rc}`);
  const plan = mem().slice(P.parser_plan(), P.parser_plan() + Signer.LAYOUT.plan.size);
  const S = await Signer.load(signerWasm, pin);
  try {
    S.init({ testnet: true }).seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
    if (registered) S.multisigLoad(registered);
    S.setPlan(plan).review();
    const sigs = S.sign();
    sigs.forEach((s, i) => mem().set(s.raw, P.parser_sigs() + i * Signer.LAYOUT.sig.size));
    mem().fill(0, P.parser_nonce_points(), P.parser_nonce_points() + 32 * 33);
    const len = P.parser_finalize(sigs.length);
    if (len < 0) throw new Error(`parser_finalize: ${len}`);
    return { psbt: mem().slice(P.parser_output(), P.parser_output() + len), n: sigs.length };
  } finally {
    S.unload();
  }
}

cli("createwallet", "miner");
const mine = (n) => cli("-rpcwallet=miner", "generatetoaddress", String(n), cli("-rpcwallet=miner", "getnewaddress"));
mine(101);
const pay = cli("-rpcwallet=miner", "getnewaddress");

let failed = 0;
for (const [name, policy, signs, lock] of CASES) {
  const height = Number(cli("getblockcount"));
  const h = height + 3 + (lock?.after ?? 0); // after() set past the funding block, so the first try is early
  // public: every key public; signing: the cosigners Core signs for with their private keys
  const wsh = (signing, step) => {
    const keys = { o: `${pub(OURS)}/${step(0)}/*`, o2: `${pub(OURS)}/${step(2)}/*`, h };
    for (const [c, k] of Object.entries(COSIGNERS)) keys[c] = `${signing && signs.includes(c) ? k : pub(k)}/${step(0)}/*`;
    return `wsh(${policy.replace(/\{(\w+)\}/g, (_, k) => keys[k])})`;
  };
  const wallet = (signing) => JSON.stringify([{ desc: withChecksum(wsh(signing, (s) => s)), range: [0, 0] }]);
  const registered = policy.includes("{o2}") ? wsh(false, (s) => `<${s};${s + 1}>`) : null;
  const withCore = (psbt, signing) => json("descriptorprocesspsbt", psbt, wallet(signing), "ALL", "true", "false").psbt;
  const [address] = json("deriveaddresses", JSON.parse(wallet(false))[0].desc, "[0,0]");
  const txid = cli("-rpcwallet=miner", "sendtoaddress", address, "0.001");
  mine(1);
  const vout = json("getrawtransaction", txid, "true").vout.find((o) => o.scriptPubKey.address === address).n;

  // the recovery path waits on the input's sequence (older) or the transaction's locktime (after)
  const sequence = lock?.older ?? 0xfffffffd, locktime = lock?.after !== undefined ? h : 0;
  const unsigned = cli("createpsbt", JSON.stringify([{ txid, vout, sequence }]), JSON.stringify([{ [pay]: 0.0009 }]),
                       String(locktime));
  const filled = withCore(unsigned, false);
  const ours = await signHere(Buffer.from(filled, "base64"), registered);
  const both = withCore(Buffer.from(ours.psbt).toString("base64"), true), alone = withCore(filled, true);
  const problems = [];
  if (ours.n !== (registered ? 2 : 1)) problems.push(`signer.wasm made ${ours.n} signatures`);
  if (json("finalizepsbt", alone).complete) problems.push("Core finalized it without our signature");
  const fin = json("finalizepsbt", both);
  if (!fin.complete) {
    problems.push("not finalizable with our signature");
  } else {
    const early = json("testmempoolaccept", JSON.stringify([fin.hex]))[0];
    if (lock && early.allowed) problems.push("accepted before its timelock");
    if (lock) mine(lock.older ?? h - Number(cli("getblockcount")));
    const late = json("testmempoolaccept", JSON.stringify([fin.hex]))[0];
    if (!late.allowed) problems.push(`refused: ${late["reject-reason"]}`);
    else {
      const spent = cli("sendrawtransaction", fin.hex);
      mine(1);
      if (!json("getrawtransaction", spent, "true").confirmations) problems.push("not mined");
    }
  }
  console.log(`${problems.length ? "FAIL" : "ok  "} ${name}${problems.length ? `: ${problems.join("; ")}` : ""}`);
  failed += problems.length ? 1 : 0;
}
console.log(`\n${CASES.length - failed} of ${CASES.length} spent with signer.wasm's signature`);
process.exit(failed ? 1 : 0);
