[![Build Status](https://travis-ci.org/javisantos/faythe.svg?branch=sodium-native)](https://travis-ci.org/javisantos/faythe) [![Coverage Status](https://coveralls.io/repos/github/javisantos/faythe/badge.svg?branch=master)](https://coveralls.io/github/javisantos/faythe?branch=sodium-native)

# Faythe

An easy crypto library to send messages using key encapsulation. A courier for Alice, Bob and friends.

## Why

Mainly to learn crypto, and i wanted to have a pure javascript library that works in the browser and node with a simple api. Another requirement was that it had to be versioned and with fixed constants.

## Installation

```sh
npm install faythe --save
```

## Usage

```js
const faythe = require('faythe').v1

const Alice = new faythe.Identity()
const Bob = new faythe.Identity()
const packed = faythe.packMessage('Hello world', [Bob], Alice)
const unpacked = faythe.unpackMessage(packed, Bob).toString()
console.log(unpacked) // Hello world
```

## API

#### `faythe.packMessage(message, recipientPublicKeys, [senderKeys], [nonRepubiable])`

Returns an object, with the encrypted message and the keys to decrypt for each recipient. If no `senderKeys`, the message is packed anonymously. Follows some [Aries RFC 0019](https://github.com/hyperledger/aries-rfcs/blob/master/features/0019-encryption-envelope/README.md) specs, but can't be considered an implementation. 


`recipientPublicKeys` an array of publicKeys

`senderKeys` an object with publicKey and privateKey

`nonRepubiable` false by default. Boolean to sign or not the message. 


#### `faythe.unpackMessage(packed, recipientKeys)`

Returns the `message` decrypted or `null` if something went wrong.

#### `faythe.generateKeyPair()`

Returns an object with an ed25519 `publicKey` and `privateKey` 

#### `faythe.hash(data)`

Returns a 32 bytes `Blake2b` hashed buffer 

`data` can be a buffer, uintArray or string

#### `faythe.derive (key, name, namespace)`

HMAC-based Extract-and-Expand Key Derivation Function. Implements HKDF from RFC5869.

`key` is a high-entropy secret key (not a password)

`name` is a non-secret random value. (salt)

`namespace` is application- and/or context-specific information

#### `faythe.precomputeSharedKey (myPrivateKey, theirPublicKey)`

Returns a shared secret between a public and private keys. Uses `diffieHellman`.

#### `faythe.authEncrypt (theirPublicKey, myPrivateKey, data, [nonce])`

Authenticated (asymmetric) encryption between a public and private keys. The `nonce` is randomly generated if not present, then, concatenated to de begining of the ciphertext. Uses `XChaCha20Poly1305`.

#### `faythe.authDecrypt (theirPublicKeyObject, myPrivateKeyObject, data, [nonce])`

Authenticated (asymmetric) decryption between a public and private keys. If `nonce` is not present, is extracted from the ciphertext.

#### `faythe.secretEncrypt (sharedSecret, data, [nonce], [AAD])`

Anonymous (symmetric) encryption usin a common `sharedSecret`. `AAD` for addional data. Uses `XChaCha20Poly1305`.

#### `faythe.secretDecrypt (sharedSecret, data, [nonce], [AAD])`

Anonymous (symmetric) decryption usin a common `sharedSecret`.

#### `faythe.sign (myKeys, data, [salt])`

Returns the signature of data with from the given keys. The `salt` is optional, concats with data.

#### `faythe.verify (publicKey, data, signature, [salt])`

Verifies the signature from the given publicKey.

## Identity

#### `new faythe.Identity(masterkey, name, namespace)`

Faythe export this class to easy manage identity related features. WIP


## Dependencies

- [@stablelib/blake2b](https://ghub.io/@stablelib/blake2b): BLAKE2b cryptographic hash function
- [@stablelib/cbor](https://ghub.io/@stablelib/cbor): CBOR encoder and decoder
- [@stablelib/ed25519](https://ghub.io/@stablelib/ed25519): Ed25519 public-key signature (EdDSA with Curve25519)
- [@stablelib/hkdf](https://ghub.io/@stablelib/hkdf): HMAC-based Extract-and-Expand Key Derivation Function (HKDF, RFC 5869)
- [@stablelib/newhope](https://ghub.io/@stablelib/newhope): NewHope post-quantum secure key agreement
- [@stablelib/x25519](https://ghub.io/@stablelib/x25519): X25519 key agreement (Curve25519)
- [@stablelib/xchacha20poly1305](https://ghub.io/@stablelib/xchacha20poly1305): XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-01)
- [canonicalize](https://ghub.io/canonicalize): JSON canonicalize function 
- [esm](https://ghub.io/esm): Tomorrow&#39;s ECMAScript modules today!
- [multibase](https://ghub.io/multibase): JavaScript implementation of the multibase specification

## Dev Dependencies

- [@babel/core](https://ghub.io/@babel/core): Babel compiler core.
- [@babel/plugin-transform-runtime](https://ghub.io/@babel/plugin-transform-runtime): Externalise references to helpers and builtins, automatically polyfilling your code without polluting globals
- [@babel/preset-env](https://ghub.io/@babel/preset-env): A Babel preset for each environment.
- [@rollup/plugin-commonjs](https://ghub.io/@rollup/plugin-commonjs): Convert CommonJS modules to ES2015
- [@rollup/plugin-node-resolve](https://ghub.io/@rollup/plugin-node-resolve): Locate and bundle third-party dependencies in node_modules
- [@rollup/plugin-replace](https://ghub.io/@rollup/plugin-replace): Replace strings in files while bundling
- [babelify](https://ghub.io/babelify): Babel browserify transform
- [browserify](https://ghub.io/browserify): browser-side require() the node way
- [coveralls](https://ghub.io/coveralls): takes json-cov output into stdin and POSTs to coveralls.io
- [eslint](https://ghub.io/eslint): An AST-based pattern checker for JavaScript.
- [eslint-config-standard](https://ghub.io/eslint-config-standard): JavaScript Standard Style - ESLint Shareable Config
- [eslint-plugin-html](https://ghub.io/eslint-plugin-html): A ESLint plugin to lint and fix inline scripts contained in HTML files.
- [eslint-plugin-import](https://ghub.io/eslint-plugin-import): Import with sanity.
- [eslint-plugin-node](https://ghub.io/eslint-plugin-node): Additional ESLint&#39;s rules for Node.js
- [eslint-plugin-promise](https://ghub.io/eslint-plugin-promise): Enforce best practices for JavaScript promises
- [eslint-plugin-standard](https://ghub.io/eslint-plugin-standard): ESlint Plugin for the Standard Linter
- [https-pem](https://ghub.io/https-pem): Self-signed PEM key and certificate ready for use in your HTTPS server
- [lerna](https://ghub.io/lerna): A tool for managing JavaScript projects with multiple packages.
- [nyc](https://ghub.io/nyc): the Istanbul command line interface
- [rollup](https://ghub.io/rollup): Next-generation ES module bundler
- [rollup-plugin-browserify-transform](https://ghub.io/rollup-plugin-browserify-transform): Use Browserify transforms with Rollup
- [rollup-plugin-node-globals](https://ghub.io/rollup-plugin-node-globals): insert the same globals browserify does
- [rollup-plugin-node-polyfills](https://ghub.io/rollup-plugin-node-polyfills): An easy crypto library to send messages using key encapsulation. A courier for Alice and Bob.
- [rollup-plugin-terser](https://ghub.io/rollup-plugin-terser): Rollup plugin to minify generated es bundle
- [tap-nyc](https://ghub.io/tap-nyc): nyc compatible TAP output formatter
- [tap-spec](https://ghub.io/tap-spec): Formatted TAP output like Mocha&#39;s spec reporter
- [tape](https://ghub.io/tape): tap-producing test harness for node and browsers

## License

MIT

Copyright (c) 2020 Javi Santos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
