# 2.0.0

- Breaking change: Add dependency on BigInt support for all operations
  - Previously only necessary when using USE_STARKWARE_CPP=true
- DEPRECATE C++ bindings
- Breaking change, remove all references to `elliptic` and `bn.js`
  - `generateKey` now returns the hex encoded private Key instead of elliptic KeyPair (no hex prefix)

## Migration guide

```js
// @sorare.crypto@^1.0.0
const keypair = generateKey();
const privateKey = exportPrivateKey(keypair);
const publicKey = exportPublicKey(keypair);

// @sorare/crypto@2.0.0
const privateKey = generateKey();
const publicKey = exportPublicKey(privateKey);
```
