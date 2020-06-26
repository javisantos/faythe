// eslint-disable-next-line
require = require('esm')(module)

const test = require('tape')
const faythe = require('../src/v1')

let alice, bob, charlie

['node', 'browser'].forEach((env) => {
  test('Init (' + env + ')', (t) => {
    t.assert(faythe.VERSION === '1', 'Should be v1')
    if (env === 'browser') {
      process.browser = true
    } else {
      process.browser = false
    }
    alice = faythe.generateKeyPair()
    bob = faythe.generateKeyPair()
    charlie = faythe.generateKeyPair()
    t.end()
  })

  test('random (' + env + ')', (t) => {
    const rnd = faythe.randomBytes(32)
    t.equal(rnd.length, 32, 'Should be 32 bytes long')
    t.end()
  })

  test('hash (' + env + ')', (t) => {
    const hash = faythe.hash('Hello world')
    t.equal(hash.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    t.end()
  })

  test('generateKeyPair (' + env + ')', (t) => {
    const kp = faythe.generateKeyPair()
    t.equal(kp.publicKey.length, faythe.PUBLICKEYBYTES, `Should be ${faythe.PUBLICKEYBYTES} bytes long`)
    t.equal(kp.privateKey.length, faythe.PRIVATEKEYBYTES, `Should be ${faythe.PRIVATEKEYBYTES} bytes long`)
    t.end()
  })

  test('sharedKey (' + env + ')', (t) => {
    const sharedKey = faythe.precomputeSharedKey(alice.privateKey, bob.publicKey)

    t.equal(sharedKey.length, 32, 'Shoud be 32 bytes long')
    t.end()
  })

  test('SecretEncrypt (' + env + ')', (t) => {
    const sharedKey = faythe.randomBytes(32)
    const data = 'Hello world'
    const nonce = faythe.randomBytes(faythe.NONCEBYTES)
    const encrypted = faythe.secretEncrypt(sharedKey, data, nonce)
    const decrypted = faythe.secretDecrypt(sharedKey, encrypted, nonce)
    t.equal(decrypted.toString(), 'Hello world', 'Should encrypt and decrypt')

    const encryptedaad = faythe.secretEncrypt(sharedKey, data, nonce, Buffer.from('aad'))
    const decryptedaad = faythe.secretDecrypt(sharedKey, encryptedaad, nonce, Buffer.from('aad'))
    t.equal(decryptedaad.toString(), 'Hello world', 'Should encrypt and decrypt with aad')

    try {
      faythe.secretEncrypt('invalid', data, nonce, Buffer.from('aad'))
    } catch (error) {
      t.equal(error.message, 'First argument must be Buffer', 'Should throw if no Buffer1')
    }

    try {
      faythe.secretEncrypt(sharedKey, {}, nonce, Buffer.from('aad'))
    } catch (error) {
      t.equal(error.message, 'Data must be a string or Buffer', 'Should throw if no string or Buffer2')
    }

    try {
      faythe.secretEncrypt(sharedKey, data, faythe.randomBytes(1), Buffer.from('aad'))
    } catch (error) {
      t.equal(error.message, `Nonce must be a Buffer of ${faythe.NONCEBYTES} length`, 'Should throw if invalid nonce')
    }

    try {
      faythe.secretEncrypt(sharedKey, data, nonce, {})
    } catch (error) {
      t.equal(error.message, 'AAD must be a Buffer', 'AAD Should throw if no Buffer')
    }

    try {
      faythe.secretEncrypt(sharedKey, data)
    } catch (error) {
      t.equal(error.message, `Nonce must be a Buffer of ${faythe.NONCEBYTES} length`, 'Should throw if no nonce')
    }

    t.end()
  })

  test('AuthEncrypt (' + env + ')', (t) => {
    const data = 'Hello world'
    const nonce = faythe.randomBytes(faythe.NONCEBYTES)
    const encrypted = faythe.authEncrypt(bob.publicKey, alice.privateKey, data, nonce)
    const decrypted = faythe.authDecrypt(bob.publicKey, alice.privateKey, encrypted, nonce)
    t.equal(decrypted.toString(), 'Hello world', 'Should encrypt and decrypt')

    try {
      faythe.authEncrypt(bob.publicKey, alice.privateKey, data)
    } catch (error) {
      t.equal(error.message, `Nonce must be a Buffer of ${faythe.NONCEBYTES} length`, 'Should throw if no nonce')
    }

    try {
      faythe.authEncrypt('invalid', alice.privateKey, data, nonce)
    } catch (error) {
      t.equal(error.message, 'First argument must be a publicKey', 'Should throw if invalid publicKey')
    }

    try {
      faythe.authEncrypt(bob.publicKey, 'invalid', data, nonce)
    } catch (error) {
      t.equal(error.message, 'Second argument must be a privateKey', 'Should throw if invalid privateKey')
    }

    try {
      faythe.authEncrypt(bob.publicKey, alice.privateKey, { invalid: true }, nonce)
    } catch (error) {
      t.equal(error.message, 'Data must be a string or Buffer', 'Should throw if data is not string or Buffer')
    }

    try {
      faythe.authEncrypt(bob.publicKey, alice.privateKey, data, faythe.randomBytes(1))
    } catch (error) {
      t.equal(error.message, `Nonce must be a Buffer of ${faythe.NONCEBYTES} length`, `Should throw if nonce is not ${faythe.NONCEBYTES} length`)
    }

    t.end()
  })

  test('SecretEncrypt without nonce (' + env + ')', (t) => {
    const sharedKey = faythe.randomBytes(32)
    const data = 'Hello world'

    const encrypted = faythe.secretEncrypt(sharedKey, data)
    const decrypted = faythe.secretDecrypt(sharedKey, encrypted)
    t.equal(decrypted.toString(), 'Hello world', 'Should encrypt and decrypt without sending nonce')
    t.end()
  })

  test('AnonEncrypt (' + env + ')', (t) => {
    const data = 'Hello world'
    const encrypted = faythe.anonEncrypt(bob.publicKey, data)
    const decrypted = faythe.anonDecrypt(bob, encrypted)
    t.equal(decrypted.toString(), 'Hello world', 'Should encrypt and decrypt')

    t.end()
  })

  test('Packmessage (' + env + ')', (t) => {
    const message = 'Hello World'
    const packed = faythe.packMessage(message, [bob.publicKey], alice)
    const unpacked = faythe.unpackMessage(packed, bob)
    t.equal(unpacked.toString(), message, 'Should pack and unpack')

    t.end()
  })

  test('Packmessage errors (' + env + ')', (t) => {
    const message = 'Hello World'
    const packed = faythe.packMessage(message, [bob.publicKey], alice)

    const wrongversion = faythe.encode(Buffer.from(JSON.stringify({ typ: 'wrong' })))
    packed.protected = wrongversion
    const unpackedwrong = faythe.unpackMessage(packed, bob)
    t.equal(unpackedwrong, false, 'Should not unpack')

    packed.protected = Buffer.from(JSON.stringify({})).toString('base64')
    const unpackedinvalid = faythe.unpackMessage(packed, bob)
    t.equal(unpackedinvalid, false, 'Should not unpack')
    t.end()
  })

  test('Packmessage json (' + env + ')', (t) => {
    const message = { greetings: 'Hello World' }
    const packed = faythe.packMessage(message, [bob.publicKey], alice)
    const unpacked = faythe.unpackMessage(packed, bob)
    t.equal(unpacked.toString(), JSON.stringify(message), 'Should pack and unpack')

    packed.protected = Buffer.from(JSON.stringify({})).toString('base64')
    const unpackedinvalid = faythe.unpackMessage(packed, bob)
    t.equal(unpackedinvalid, false, 'Should not unpack')

    t.end()
  })

  test('Pack message for multiple recipients (' + env + ')', (t) => {
    const message = 'Hello World'
    const packed = faythe.packMessage(message, [bob.publicKey, charlie.publicKey], alice)
    const unpackedbob = faythe.unpackMessage(packed, bob)
    t.equal(unpackedbob.toString(), message, 'Should unpack for bob')
    const unpackedcharlie = faythe.unpackMessage(packed, bob)
    t.equal(unpackedcharlie.toString(), message, 'Should unpack for charlie')
    t.end()
  })

  test('Pack Anonymous message (' + env + ')', (t) => {
    const message = 'Hello World'
    const packed = faythe.packMessage(message, [bob.publicKey])
    const unpacked = faythe.unpackMessage(packed, bob)
    t.equal(unpacked.toString(), message, 'Should pack and unpack')
    t.end()
  })

  test('Sign (' + env + ')', (t) => {
    const alice = faythe.generateKeyPair()
    const data = 'Hello World'
    const signature = faythe.sign(alice, data)
    const verified = faythe.verify(alice.publicKey, data, signature)
    t.assert(verified, 'Should sign and verify')
    const salt = faythe.randomBytes(faythe.SALTBYTES)
    const signaturesalt = faythe.sign(alice, data, salt)
    const verifiedsalt = faythe.verify(alice.publicKey, data, signaturesalt, salt)
    t.assert(verifiedsalt, 'Should sign and verify with salt')
    t.end()
  })

  test('Sign an object (' + env + ')', (t) => {
    const alice = faythe.generateKeyPair()
    const data = { ops: '1', greetings: 'Hello World' }
    const signature = faythe.sign(alice, data)
    const verified = faythe.verify(alice.publicKey, { greetings: 'Hello World', ops: '1' }, signature)
    t.assert(verified, 'Should sign and verify a disordered object')
    const salt = faythe.randomBytes(faythe.SALTBYTES)
    const signaturesalt = faythe.sign(alice, data, salt)
    const verifiedsalt = faythe.verify(alice.publicKey, data, signaturesalt, salt)
    t.assert(verifiedsalt, 'Should sign and verify with salt')
    t.end()
  })

  test('Pack non repudiable message (' + env + ')', (t) => {
    const kp = faythe.generateKeyPair()
    const message = 'Hello World'
    const packed = faythe.packMessage(message, [bob.publicKey], kp, true)
    const unpacked = faythe.unpackMessage(packed, bob)
    t.equal(unpacked.toString(), message, 'Should pack and unpack')

    try {
      faythe.packMessage(message, [bob.publicKey], alice, true)
    } catch (error) {
      t.equal(error.message, "Non repudiable message require sender's verification key", 'Should throw if no verification key')
    }

    packed.signature = 'invalid'
    const unpackedinvalid = faythe.unpackMessage(packed, bob)
    t.equal(unpackedinvalid, false, 'Should not unpack if signature is invalid')
    t.end()
  })

  test('Derive (' + env + ')', (t) => {
    const derived = faythe.derive(Buffer.alloc(32, 'test'), 'Alice2', 'test')
    t.deepEqual(derived.toString('hex'), '61b109ff5f3ba18fe1de971188fd650c37c52344e6cac33b4a47b6da9121c819', 'Should derive a key')
    t.end()
  })

  test('Identity toJson (' + env + ')', (t) => {
    const Alice = new faythe.Identity()
    t.deepEqual(Alice.toJson().type, 'Ed25519VerificationKey2018', 'Should return a Ed25519VerificationKey2018')
    t.end()
  })

  test('Identity keyExchange post-quantum (' + env + ')', (t) => {
    const Alice = new faythe.Identity()
    const Bob = new faythe.Identity()

    const AlicesOffer = Alice.offer('Bob')
    const BobAccept = Bob.accept(AlicesOffer, 'Alice')

    Alice.finish(BobAccept, 'Bob')

    t.deepEqual(Alice.sharedKeys.get('Bob'), Bob.sharedKeys.get('Alice'), 'Should share the same key')
    t.end()
  })

  test('Identity X25591 sharedKey (' + env + ')', (t) => {
    const Alice = new faythe.Identity()
    const Bob = new faythe.Identity()
    const AlicesSharedKey = Alice.sharedKey(Bob)
    const BobSharedKey = Bob.sharedKey(Alice.publicKey)

    t.deepEqual(AlicesSharedKey, BobSharedKey, 'Should share the same key')
    t.end()
  })
})
