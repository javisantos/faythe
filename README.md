[![Build Status](https://travis-ci.org/javisantos/faythe.svg?branch=master)](https://travis-ci.org/javisantos/faythe) [![Coverage Status](https://coveralls.io/repos/github/javisantos/faythe/badge.svg?branch=master)](https://coveralls.io/github/javisantos/faythe?branch=master)

# Faythe

An easy crypto library to send messages using key encapsulation. A courier for Alice, Bob and friends.

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
