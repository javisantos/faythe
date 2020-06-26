const faythe = require('.').v1

const Alice = new faythe.Identity()
const Bob = new faythe.Identity()
const packed = faythe.packMessage('Hello world', [Bob], Alice)
const unpacked = faythe.unpackMessage(packed, Bob).toString()
console.log(unpacked) // Hello world
