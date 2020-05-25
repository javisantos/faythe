const faythe = require('.').v1

const Alice = faythe.generateKeyPair()
const Bob = faythe.generateKeyPair()
const packed = faythe.packMessage('Hello world', [Bob.publicKey], Alice)
const unpacked = faythe.unpackMessage(packed, Bob).toString()
console.log(unpacked) // Hello world
