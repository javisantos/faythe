// eslint-disable-next-line
require = require('esm')(module)

const test = require('tape')
const faythe = require('../src/v1')

let alice, bob, charlie

['node'].forEach((env) => {
  test('Ready (' + env + ')', async (t) => {
    t.assert(faythe.VERSION === '1.0', 'Should be v1')
  })

  test('Init (' + env + ')', async (t) => {
    alice = alice || new faythe.Identity('test', 'alice', 'secret')

    bob = bob || new faythe.Identity()
    charlie = charlie || new faythe.Identity('test', 'charlie', null, null, 1)
    t.end()
  })

  test('fromMnemonic (' + env + ')', (t) => {
    const alice2 = faythe.Identity.fromMnemonic(alice.mnemonic, 'test', 'alice', 'secret')
    t.equal(alice.publicKey.toString('hex'), alice2.publicKey.toString('hex'), 'Should be the same')
    t.equal(alice.privateKey.toString('hex'), alice2.secretKey.toString('hex'), 'Should be the same')

    const bob2 = faythe.Identity.fromMnemonic(bob.mnemonic)
    t.equal(bob.publicKey.toString('hex'), bob2.publicKey.toString('hex'), 'Should be the same')

    const charlie2 = faythe.Identity.fromMnemonic(charlie.mnemonic, 'test', 'charlie', null, 1)
    t.equal(charlie.publicKey.toString('hex'), charlie2.publicKey.toString('hex'), 'Should be the same')
    t.end()
  })

  test('fromEntropy (' + env + ')', (t) => {
    const alice3 = faythe.Identity.fromEntropy(alice.entropy, 'test', 'alice', 'secret')
    t.equal(alice.publicKey.toString('hex'), alice3.publicKey.toString('hex'), 'Should be the same')
    const alice4 = faythe.Identity.fromMnemonic(alice3.mnemonic, 'test', 'alice', 'secret')
    t.equal(alice3.publicKey.toString('hex'), alice4.publicKey.toString('hex'), 'Should be the same')
    try {
      const _ = faythe.Identity.fromMnemonic(null)
      _.lock()
    } catch (error) {
      t.equal(error.message, 'Mnemonic is required', 'Should throw')
    }
    try {
      const _ = faythe.Identity.fromEntropy(Buffer.alloc(16))
      _.lock()
    } catch (error) {
      t.equal(error.message, 'Invalid entropy', 'Should throw')
    }
    t.end()
  })

  test('export (' + env + ')', (t) => {
    const exported = alice.export()
    const imported = alice.import(exported)
    const c = imported.find((c) => c.name === 'alice' && c.type === 'Ed25519VerificationKey2018')
    t.equal(
      alice.keyPairFor(faythe.decode(c.idspace), c.name).publicKey.toString('hex'),
      alice.publicKey.toString('hex'), 'Should import and export')
    t.end()
  })

  test('lock (' + env + ')', (t) => {
    const prevPk = alice.publicKey.toString('hex')
    alice.lock()
    const lockedkp = alice.keyPairFor('lock')
    t.equal(lockedkp, null, 'Should be null')
    alice = alice.unlock('secret')
    const unlockedkp = alice.keyPairFor('unlock')
    t.equal(unlockedkp.publicKey.length, 32, 'Should allow after unlock')
    t.equal(alice.publicKey.toString('hex'), prevPk, 'Should be the same')
    t.end()
  })

  test('keyPairFor (' + env + ')', (t) => {
    const kpf = alice.keyPairFor('test', 'alice', { tags: ['test'], description: 'Keypair for idspace alice/test' })
    t.equal(kpf.publicKey.toString('hex'), alice.publicKey.toString('hex'), 'Should be the same')
    const tags = alice.keyPairFor('personal', null, { tags: ['personal'], description: 'Keypair for idspace alice/personal' })
    t.deepEqual(tags.tags, ['keyPair', 'verification', 'personal'], 'Should add tags')
    try {
      alice.keyPairFor()
    } catch (error) {
      t.equal(error.message, 'Idspace is required', 'Should throw')
    }
    const kpencoded = alice.keyPairFor(faythe.decode(kpf.idspace), 'alice')
    t.equal(kpencoded.publicKey.toString('hex'), alice.publicKey.toString('hex'), 'Should be the same!!')
    console.log(alice.contents)
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
    const hash2 = faythe.hash('Hello world', 32, hash)
    t.equal(hash.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    t.equal(hash2.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    t.end()
  })

  test('sha256 (' + env + ')', (t) => {
    const hash = faythe.sha256('Hello world')
    t.equal(hash.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    t.equal(hash.toString('hex'), '64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c')
    t.end()
  })

  test('hashBatch (' + env + ')', (t) => {
    const hash = faythe.hashBatch(['Hello world', 'Hello world'])
    t.equal(hash.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    const hash2 = faythe.hashBatch(['Hello world', 'Hello world'], 32, hash)
    t.equal(hash2.length, faythe.HASHBYTES, `Should be ${faythe.HASHBYTES} bytes long`)
    t.end()
  })

  test('generateKeyPair (' + env + ')', (t) => {
    const kp = faythe.generateKeyPair()
    t.equal(kp.publicKey.length, faythe.PUBLICKEYBYTES, `Should be ${faythe.PUBLICKEYBYTES} bytes long`)
    t.equal(kp.privateKey.length, faythe.PRIVATEKEYBYTES, `Should be ${faythe.PRIVATEKEYBYTES} bytes long`)
    t.end()
  })

  test('sharedKey (' + env + ')', (t) => {
    const sharedKey = faythe.precomputeSharedKey(alice.privateKey, bob.publicKey, true)
    const sharedKey2 = faythe.precomputeSharedKey(bob.privateKey, alice.publicKey)
    t.equal(sharedKey.length, 32, 'Shoud be 32 bytes long')
    t.equal(sharedKey.toString('hex'), sharedKey2.toString('hex'), 'Shoud compute same key')
    t.end()
  })

  test('toCurve25519 (' + env + ')', (t) => {
    const toCurve25519Kp = faythe.generateKeyPair(Buffer.alloc(32, 1))
    const curvePK = faythe.toCurve25519(toCurve25519Kp.publicKey, 'public')
    const curveSK = faythe.toCurve25519(toCurve25519Kp.privateKey, 'private')
    t.equal(toCurve25519Kp.publicKey.toString('hex'), '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')
    t.equal(curvePK.toString('hex'), '1b1b58dd50ea14b60da17b790cd02754d970c9bab864ebb3c0f3016fe51d3f57')
    t.equal(curveSK.toString('hex'), '58e86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef36e')

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
    const decrypted = faythe.authDecrypt(alice.publicKey, bob.privateKey, encrypted, nonce)
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
    const packed = faythe.packMessage(message, [bob], alice)
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
    const derived = faythe.derive(Buffer.alloc(32, 'test'), 'test', 'Alice2')
    t.deepEqual(derived.toString('hex'), '7de8fd0627eb12f948166b0e0e6a4a58a4d4382c4189b0af49f5eb1ff3907420', 'Should derive a key')
    t.end()
  })

  test('Derive from key (' + env + ')', (t) => {
    const derived1 = faythe.deriveFromKey(Buffer.alloc(32, 'test'), 0, 'test')
    t.deepEqual(derived1.toString('hex'), '33606ba143d424144e9258a30c57655b88523f15e7c3097b67e3f97743da2a5d', 'Should derive from key')
    const derived2 = faythe.deriveFromKey(Buffer.alloc(32, 'test'), 1, 'test')
    t.deepEqual(derived2.toString('hex'), 'a21e1edde5a9de862ef62f8417bfbd8213e4eea4977fef9b53bc26719b7c6eab', 'Should derive from key')

    t.end()
  })

  test('Identity toJson (' + env + ')', (t) => {
    t.deepEqual(alice.toJson().type, 'Ed25519VerificationKey2018', 'Should return a Ed25519VerificationKey2018')
    t.end()
  })

  test('Noise NN (' + env + ')', (t) => {
    const { offer } = alice.offer('bob')
    const accept = bob.accept('alice', offer)
    alice.finish('bob', accept)
    t.equal(alice.contents.find((c) => c.name === 'bob').sharedKeys.tx.toString('hex'), bob.contents.find((c) => c.name === 'alice').sharedKeys.rx.toString('hex'), 'Should have same shared key')

    t.end()
  })
})
