[![Build Status](https://travis-ci.org/javisantos/faythe.svg?branch=master)](https://travis-ci.org/javisantos/faythe) [![Coverage Status](https://coveralls.io/repos/github/javisantos/faythe/badge.svg?branch=master)](https://coveralls.io/github/javisantos/faythe?branch=master)

# Faythe

An easy crypto library to send messages using key encapsulation. A courier for Alice, Bob and friends.

## Why

Mainly to learn crypto, and i wanted to have library that works in the browser and node with a simple api. Another requirement was that it had to be versioned and with fixed constants.

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

#### `faythe.generateKeyPair([seed])`

Returns an object with an ed25519 `publicKey` and `privateKey` 

#### `faythe.hash(data,[[bytes], [key]])`

Returns a 32 bytes `Blake2b` hashed buffer 

`data` can be a buffer, uintArray or string

#### `faythe.derive (key, [[namespace], [name]])`

Uses blake2b to derive a 32 bytes key

#### `faythe.precomputeSharedKey (myPrivateKey, theirPublicKey, [initiator])`

Returns a shared secret between a public and private keys. Uses `diffieHellman`.

#### `faythe.authEncrypt (theirPublicKey, myPrivateKey, data, [nonce])`

Authenticated (asymmetric) encryption between a public and private keys. The `nonce` is randomly generated if not present, then, concatenated to de begining of the ciphertext. Uses `XChaCha20Poly1305`.

#### `faythe.authDecrypt (theirPublicKey, myPrivateKey, data, [nonce])`

Authenticated (asymmetric) decryption between a public and private keys. If `nonce` is not present, is extracted from the ciphertext. Uses `XChaCha20Poly1305`.

#### `faythe.secretEncrypt (secretKey, data, [[nonce], [AAD]])`

Anonymous (symmetric) encryption usin a common `sharedSecret`. `AAD` for addional data. Uses `XChaCha20Poly1305`.

#### `faythe.secretDecrypt (secretKey, data, [[nonce], [AAD]])`

Anonymous (symmetric) decryption usin a common `sharedSecret`. Uses `XChaCha20Poly1305`.

#### `faythe.sign (myKeys, data, [salt])`

Returns the signature of data from the given keys. The `salt` is optional, concats with data.

#### `faythe.verify (publicKey, data, signature, [salt])`

Verifies the signature from the given publicKey.

## Identity

#### `new faythe.Identity([[idspace], [name], [passphrase], [rotation], [mnemonic], [seed]])`

Faythe export this class to easy manage identity related features. WIP

See test folder for Identity management examples

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
