# Releases

How a release is produced, and how you check one.

## Checking a release

```sh
# 1. the hashes of both modules match the manifest
sha256sum -c SHA256SUMS

# 2. the file was built by this repository's release workflow, from this tag
TAG=vX.Y.Z
ID=https://github.com/bitwasm-project/bitwasm-signer/.github/workflows/release.yml@refs/tags/$TAG
gh attestation verify parser.wasm --repo bitwasm-project/bitwasm-signer --cert-identity "$ID" --deny-self-hosted-runners
gh attestation verify signer.wasm --repo bitwasm-project/bitwasm-signer --cert-identity "$ID" --deny-self-hosted-runners
```

`--repo` alone accepts an attestation from any workflow in the repository, on any branch.
`--cert-identity` narrows it to the release workflow run for the tag you downloaded.

Releases up to v0.3.0 were built before this repository moved from `habakan` to `bitwasm-project`.
Their attestations are stored under the old owner and name the old path, so check them like this:

```sh
TAG=v0.3.0
ID=https://github.com/habakan/bitwasm-signer/.github/workflows/release.yml@refs/tags/$TAG
gh attestation verify parser.wasm --owner habakan --cert-identity "$ID" --deny-self-hosted-runners
gh attestation verify signer.wasm --owner habakan --cert-identity "$ID" --deny-self-hosted-runners
```

Releases are not signed with the maintainer's GPG key. Step 2 relies on GitHub's signing of the
build, and the reproducible build below does not rely on anything but the source.

## Checking it yourself, without trusting any of that

The build is reproducible. Check out the tag, build with the pinned toolchain, and compare:

```sh
git checkout v0.1.0
gh release download v0.1.0 -p SHA256SUMS

# the same toolchain the release was built with, pinned by version and by the hash of its tarball
curl -sLO https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz
echo "b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4  wasi-sdk-34.0-x86_64-linux.tar.gz" | sha256sum -c -
tar xzf wasi-sdk-34.0-x86_64-linux.tar.gz
curl -sLO https://github.com/WebAssembly/binaryen/releases/download/version_132/binaryen-version_132-x86_64-linux.tar.gz
echo "195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572  binaryen-version_132-x86_64-linux.tar.gz" | sha256sum -c -
tar xzf binaryen-version_132-x86_64-linux.tar.gz

SDK=$PWD/wasi-sdk-34.0-x86_64-linux
make deps
make all \
  LLVM=$SDK/bin WASI=$SDK/share/wasi-sysroot \
  RTLIB=$SDK/lib/clang/23/lib/wasm32-unknown-wasi \
  WASM_OPT=$PWD/binaryen-version_132/bin/wasm-opt

(cd build && sha256sum -c ../SHA256SUMS)
```

The macOS arm64 tarballs (`-arm64-macos`) produce the same bytes. `make` alone uses whatever clang is
on your machine and is **not** expected to reproduce the release: the versions above are the ones that
do. [.github/workflows/ci.yml](../../.github/workflows/ci.yml) pins the build tools; the
[release workflow](../../.github/workflows/release.yml) runs it for the tagged commit.

One trap worth naming: if a different `wasm-opt` is earlier on your `PATH`, `WASM_OPT` above is what
decides, so set it explicitly as shown rather than relying on the `PATH`.

This is the strongest of the three checks: it does not require trusting the maintainer or GitHub.

You can also check the shape of what you downloaded without running it:

```sh
for module in parser.wasm signer.wasm; do
  features=-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global
  if [ "$module" = signer.wasm ]; then features="$features,sign-extension"; fi
  wasm-tools validate --features="$features" "$module"
  test "$(wasm-tools print "$module" | grep -c '^\s*(import ')" = 0
done
```

And a host can refuse anything else:

```js
await Parser.load(parserWasm, { sha256: "…" });
```

## Making a release

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The workflow runs the CI test suite for the tag, then publishes both `parser.wasm` and `signer.wasm`
from that tested build. It writes `SHA256SUMS` and attaches a build provenance attestation to each
module before creating the release.

## Keeping the hash honest

`checksums.txt` holds the hashes of the current `parser.wasm` and `signer.wasm`, and CI rebuilds with
the pinned toolchain and compares against them on every commit. A change to either module changes its
hash, and the job fails until `checksums.txt` is updated on purpose — so the files cannot quietly drift
out of step with what gets released.

## Versioning

Tags are `vMAJOR.MINOR.PATCH`. The number that matters to a host is `plan_t.version`, which is
independent: adding a field, changing a size, or changing a meaning bumps it, and a host that sees an
unknown version must refuse rather than guess. See [the ABI](abi.md#versioning).
