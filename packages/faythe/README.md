# Faythe

An easy crypto library to send messages using key encapsulation. A courier for Alice and Bob.

## Installation

```sh
npm install faythe --save
```

## Usage

```js
const faythe = require('faythe').v1

const Alice = faythe.generateKeyPair()
const Bob = faythe.generateKeyPair()
const packed = faythe.packMessage('Hello world', [Bob.publicKey], Alice)
const unpacked = faythe.unpackMessage(packed, Bob).toString()
console.log(unpacked) // Hello world

```

## License

MIT
