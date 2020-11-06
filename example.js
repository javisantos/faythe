const faythe = require('.').v1
const util = require('util')
const Alice = new faythe.Identity()
const Bob = new faythe.Identity()
const Charlie = new faythe.Identity()
const packed = faythe.packMessage('Hello world', [Bob, Charlie], Alice)
console.log(packed)
console.log(util.inspect(JSON.parse(faythe.decode(packed.protected).toString()), { colors: true, depth: 3 }))
const unpackedBob = faythe.unpackMessage(packed, Bob).toString()
const unpackedCharlie = faythe.unpackMessage(packed, Charlie).toString()
console.log(unpackedBob) // Hello world
console.log(unpackedCharlie) // Hello world
