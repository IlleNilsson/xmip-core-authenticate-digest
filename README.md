# xmip-core-authenticate-digest

Authenticate by HTTP Digest: verifies an RFC 7616 response against the stored HA1 for the realm and a nonce this node issued. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
