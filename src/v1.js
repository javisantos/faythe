import sodium from 'sodium-universal'
import cbor from 'borc'
import { EventEmitter } from 'events'
import multibase from 'multibase'
import multicodec from 'multicodec'
import canonicalize from 'canonicalize'
import { generateMnemonic, mnemonicToSeedSync, entropyToMnemonic, mnemonicToEntropy } from 'bip39'
import noise from 'noise-protocol'

export const PROTOCOL = 'FAYTHE'
export const VERSION = '1.0'
export const RANDOMBYTES = 32
export const NONCEBYTES = 12
export const HASHBYTES = 32
export const PUBLICKEYBYTES = 32
export const PRIVATEKEYBYTES = 64
export const SHAREDKEYBYTES = 32
export const SALTBYTES = 12
export const MIN_SEEDBYTES = 16
export const AUTHTAGLENGTH = 16
export const ENCODER = 'base64url'
export const SERIALIZER = 'cbor'
export const ENCRYPTIONKEYTYPE = 'X25519EncryptionKey2018'
export const VERIFICATIONKEYTYPE = 'Ed25519VerificationKey2018'
export const CIPHERALG = 'chacha20poly1305_ietf'
export const HASHALG = 'blake2b-256'
export const KDF = 'PBKDF2'
export const HANDSHAKE = 'Noise_NN_25519_ChaChaPoly_BLAKE2b'

const MASTERKEY = Symbol('MASTERKEY')
const ROTATIONKEY = Symbol('ROTATIONKEY')
const SEED = Symbol('SEED')
const ENTROPY = Symbol('ENTROPY')
const MNEMONIC = Symbol('MNEMONIC')
const PASSPHRASE = Symbol('PASSPHRASE')
const SEEDPHRASE = Symbol('SEEDPHRASE')

const encode = (buffer, encoder = ENCODER) => {
  if (!Buffer.isBuffer(buffer)) buffer = ensureBuffer(buffer)
  return Buffer.from(multibase.encode(encoder, buffer)).toString('utf-8')
}
const decode = (bufOrString) => Buffer.from(multibase.decode(bufOrString))

const serialize = cbor.encode
const deserialize = cbor.decode

export { multicodec, multibase, canonicalize, encode, decode, serialize, deserialize, generateMnemonic, mnemonicToSeedSync, entropyToMnemonic, noise }

export function randomBytes (bytes) {
  const b = Buffer.alloc(bytes)
  sodium.randombytes_buf(b)
  return b
}

export function ensureBuffer (data) {
  return Buffer.isBuffer(data) ? data : Buffer.from(data)
}

const authEncryptErrorHandler = function (args) {
  // theirPublicKeyObject, myPrivateKeyObject, data, nonce
  if (!args[0] || args[0].length !== PUBLICKEYBYTES) throw new TypeError('First argument must be a publicKey')
  if (!args[1] || args[1].length !== PRIVATEKEYBYTES) throw new TypeError('Second argument must be a privateKey')
  if (!args[2] || (typeof args[2] !== 'string' && !Buffer.isBuffer(args[2]))) throw new TypeError('Data must be a string or Buffer')
  if (!args[3] || (args[3].length !== NONCEBYTES || !Buffer.isBuffer(args[3]))) throw new TypeError(`Nonce must be a Buffer of ${NONCEBYTES} length`)
}

const secretEncryptErrorHandler = function (args) {
  // sharedSecret, data, nonce, AAD = Buffer.alloc(0)
  if (!args[0] || !Buffer.isBuffer(args[0])) throw new TypeError('First argument must be Buffer')
  if (!args[1] || (typeof args[1] !== 'string' && !Buffer.isBuffer(args[1]))) throw new TypeError('Data must be a string or Buffer')
  if (args[2] && (args[2].length !== NONCEBYTES || !Buffer.isBuffer(args[2]))) throw new TypeError(`Nonce must be a Buffer of ${NONCEBYTES} length`)
  if (args[3] && !Buffer.isBuffer(args[3])) throw new TypeError('AAD must be a Buffer')
}

export class Identity extends EventEmitter {
  constructor (idspace, opts = {}) {
    // namespace, passphrase, mnemonic, rotation, seed
    super()
    this.contents = []
    this.encryptedContents = null
    this._locked = false
    this.rotation = opts.rotation || 0
    this.seeded = !!opts.seed

    this[PASSPHRASE] = opts.passphrase || ''

    this[MNEMONIC] = opts.seed ? null : opts.mnemonic || generateMnemonic(256, randomBytes)

    this[ENTROPY] = opts.seed ? null : Buffer.from(mnemonicToEntropy(this[MNEMONIC]), 'hex')
    this[SEED] = opts.seed || Buffer.from(mnemonicToSeedSync(this[MNEMONIC], this[PASSPHRASE]).slice(0, sodium.crypto_kdf_KEYBYTES))

    this[SEEDPHRASE] = entropyToMnemonic(this[SEED])
    this.idspace = idspace ? ensureBuffer(idspace) : Buffer.from(multicodec.addPrefix('path', hash(Buffer.from('idspace'))))

    this[MASTERKEY] = deriveFromKey(this[SEED], this.rotation, '_faythe_')

    this.namespace = opts.namespace || 'default'

    this.contents.push({
      type: 'metadata',
      description: opts.description || `Identity for ${encode(this.idspace)} (${this.namespace})`,
      tags: [].concat(opts.tags || []),
      idspace: this.idspace,
      namespace: this.namespace,
      rotation: this.rotation
    })

    this.contents.push({
      type: opts.seed ? 'seed' : 'mnemonic',
      value: opts.seed ? entropyToMnemonic(opts.seed) : this[MNEMONIC]
    })

    this.keyPair = this.keyPairFor(this.idspace, this.namespace)

    this[ROTATIONKEY] = hash(generateKeyPair(derive(deriveFromKey(this[SEED], this.rotation + 1, '_faythe_'), this.idspace, this.namespace)).publicKey)

    this.on('change', () => this.export())
    this.emit('unlocked')
    this.emit('change')

    this.setMaxListeners(0)
  }

  keyPairFor (space, namespace, info = {}) {
    if (!space) throw new Error('Idspace is required')
    namespace = namespace || this.namespace

    space = ensureBuffer(space)

    if (!this.locked) {
      const exist = this.contents.find(c => c.idspace === encode(space) && c.namespace === namespace)
      const tags = ['keyPair', 'verification'].concat(info.tags || [])
      const keyPair = generateKeyPair(derive(this.masterKey, space, namespace))
      const description = info.description || `KeyPair for ${encode(space)} (${namespace})`

      const id = 'did:key:' + encode(multicodec.addPrefix('ed25519-pub', keyPair.publicKey), 'base58btc')
      const kp = {
        id,
        type: VERIFICATIONKEYTYPE,
        idspace: encode(space),
        namespace,
        description,
        tags,
        rotation: this.rotation
      }
      if (!exist) {
        this.contents.push(kp)
        this.emit('change')
      }
      return {
        ...kp,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        secretKey: keyPair.privateKey.slice(0, PRIVATEKEYBYTES - PUBLICKEYBYTES)
      }
    } else return null
  }

  offer (id) {
    const hs = noise.initialize('NN', true, Buffer.alloc(0))
    const offer = Buffer.alloc(32)
    noise.writeMessage(hs, Buffer.alloc(0), offer)
    const state = { symmetricState: hs.symmetricState, epk: hs.epk, esk: hs.esk }
    this.contents.push({
      id,
      type: 'connection',
      namespace: id,
      offer,
      state,
      status: 'offered'
    })
    this.emit('change')
    return { offer, state }
  }

  accept (id, offer) {
    const hs = noise.initialize('NN', false, Buffer.alloc(0))
    const rx = Buffer.alloc(0)
    const tx = Buffer.alloc(48)
    noise.readMessage(hs, offer, rx)
    const sharedKeys = noise.writeMessage(hs, Buffer.alloc(0), tx)
    const keyPair = generateKeyPair(sharedKeys.rx.slice(0, sodium.crypto_sign_SEEDBYTES))
    this.contents.push({
      id,
      type: 'connection',
      namespace: id,
      offer: offer,
      sharedKeys,
      keyPair,
      status: 'connected'
    })
    noise.destroy(hs)
    this.emit('change')
    return tx
  }

  finish (id, accept, state) {
    const restoreState = state || this.contents.find((c) => c.namespace === id).state
    const hs = noise.initialize('NN', true, Buffer.alloc(0), null, { publicKey: restoreState.epk, secretKey: restoreState.esk })
    hs.symmetricState = restoreState.symmetricState
    hs.messagePatterns.shift()
    const rx = Buffer.alloc(0)
    const sharedKeys = noise.readMessage(hs, accept, rx)
    this.contents = this.contents.map((c) => {
      if (c.id === id) {
        c.sharedKeys = sharedKeys
        c.keyPair = generateKeyPair(sharedKeys.rx.slice(0, sodium.crypto_sign_SEEDBYTES))
        delete c.state
        c.status = 'connected'
      }
      return c
    })
    noise.destroy(hs)
    this.emit('change')
  }

  get publicKey () {
    return this.keyPair.publicKey
  }

  get privateKey () {
    return this.keyPair.privateKey
  }

  get secretKey () {
    return this.keyPair.privateKey
  }

  get locked () {
    return this._locked
  }

  get masterKey () {
    return this[MASTERKEY]
  }

  get entropy () {
    return this[ENTROPY]
  }

  get mnemonic () {
    return this[MNEMONIC]
  }

  get seed () {
    return this[SEED]
  }

  get seedPhrase () {
    return this[SEEDPHRASE]
  }

  get rotationKey () {
    return this[ROTATIONKEY]
  }

  lock () {
    this.export()
    this.contents = []
    this.keyPair = null
    this.masterKeyPair = null
    this[MNEMONIC] = null
    this[PASSPHRASE] = null
    this[SEEDPHRASE] = null
    sodium.sodium_memzero(this[MASTERKEY])
    sodium.sodium_memzero(this[SEED])
    sodium.sodium_memzero(this[ENTROPY])
    this._locked = true
    this.emit('locked')
  }

  export () {
    this.encryptedContents = secretEncrypt(hash(this[PASSPHRASE]), Buffer.from(serialize(this.contents)))
    return this.encryptedContents
  }

  import (encrypted) {
    this.contents = deserialize(secretDecrypt(hash(this[PASSPHRASE]), encrypted))
    return this.contents
  }

  unlock (passphrase) {
    return Identity.restore(this.encryptedContents, passphrase)
  }

  toJson () {
    return {
      type: VERIFICATIONKEYTYPE,
      publicKeyMultiBase: encode(this.publicKey).toString(),
      publicKeyBase64url: encode(this.publicKey).toString().substring(1),
      publicKeyBase64: this.publicKey.toString('base64'),
      publicKeyHex: this.publicKey.toString('hex'),
      publicKeyBase58: encode(this.publicKey, 'base58btc').toString().substring(1)
    }
  }

  static fromMnemonic (idspace, mnemonic, opts = {}) {
    if (!mnemonic) throw new Error('Mnemonic is required')
    opts.mnemonic = mnemonic
    return new Identity(idspace, opts)
  }

  static fromEntropy (idspace, entropy, opts = {}) {
    if (!entropy || !Buffer.isBuffer(entropy) || entropy.length !== RANDOMBYTES) throw new Error('Invalid entropy')
    opts.mnemonic = entropyToMnemonic(entropy.toString('hex'))
    return new Identity(idspace, opts)
  }

  static fromSeedPhrase (idspace, seedPhrase, opts = {}) {
    opts.seed = Buffer.from(mnemonicToEntropy(seedPhrase), 'hex')
    const identity = new Identity(idspace, opts)
    return identity
  }

  static fromSeed (idspace, seed, opts = {}) {
    opts.seed = seed
    const identity = new Identity(idspace, opts)
    return identity
  }

  static restore (encryptedContents, passphrase) {
    const decrypted = deserialize(secretDecrypt(hash(passphrase), encryptedContents))
    const metadata = decrypted.find(c => c.type === 'metadata')
    const mnemonic = decrypted.find(c => c.type === 'mnemonic')
    const seed = decrypted.find(c => c.type === 'seed')
    let identity
    const idspace = metadata.idspace
    const opts = {
      namespace: metadata.namespace,
      rotation: metadata.rotation,
      passphrase
    }
    if (seed && !mnemonic) {
      identity = Identity.fromSeedPhrase(idspace, seed.value, opts)
    } else {
      identity = Identity.fromMnemonic(idspace, mnemonic.value, opts)
    }
    identity.contents = decrypted
    identity.emit('change')
    return identity
  }
}

export function generateKeyPair (seed = randomBytes(RANDOMBYTES)) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return {
    publicKey: pk,
    privateKey: sk
  }
}

export function hash (data, bytes, key) {
  if (Array.isArray(data)) data = data.map(d => ensureBuffer(d))
  const b = Buffer.alloc(bytes || HASHBYTES)
  if (key) sodium.crypto_generichash(b, ensureBuffer(data), key)
  else sodium.crypto_generichash(b, ensureBuffer(data))
  return b
}

export function sha256 (data) {
  const b = Buffer.alloc(HASHBYTES)
  sodium.crypto_hash_sha256(b, ensureBuffer(data))
  return b
}

export function derive (key, idspace, namespace) {
  const derived = Buffer.alloc(RANDOMBYTES)
  sodium.crypto_generichash_batch(derived, [
    Buffer.from(Buffer.byteLength(idspace, 'ascii') + '\n' + idspace, 'ascii'),
    ensureBuffer(namespace)
  ], key)

  return derived
}

export function deriveFromKey (key, int, ctx) {
  const context = Buffer.alloc(sodium.crypto_kdf_CONTEXTBYTES, ensureBuffer(ctx))
  const derived = Buffer.alloc(RANDOMBYTES)
  sodium.crypto_kdf_derive_from_key(derived, int, context, key)
  return derived
}

export function toCurve25519 (key, type) {
  let X25519
  if (type === 'public') {
    X25519 = Buffer.alloc(sodium.crypto_kx_PUBLICKEYBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(X25519, key)
  } else {
    X25519 = Buffer.alloc(sodium.crypto_kx_SECRETKEYBYTES)
    sodium.crypto_sign_ed25519_sk_to_curve25519(X25519, key)
  }
  return X25519
}

export function precomputeSharedKey (myPrivateKey, theirPublicKey, initiator) {
  const X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  const X25519sk = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, theirPublicKey)
  sodium.crypto_sign_ed25519_sk_to_curve25519(X25519sk, myPrivateKey)

  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES)

  sodium.crypto_scalarmult(
    sharedSecret,
    X25519sk,
    X25519pk
  )

  return !initiator
    ? hash(Buffer.concat([sharedSecret, myPrivateKey.subarray(sodium.crypto_sign_PUBLICKEYBYTES), theirPublicKey]))
    : hash(Buffer.concat([sharedSecret, theirPublicKey, myPrivateKey.subarray(sodium.crypto_sign_PUBLICKEYBYTES)]))
}

export function authEncrypt (theirPublicKey, myPrivateKey, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedSecret = this.precomputeSharedKey(myPrivateKey, theirPublicKey, true)
  const result = this.secretEncrypt(sharedSecret, data, nonce)
  return result
}

export function authDecrypt (theirPublicKey, myPrivateKey, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedSecret = precomputeSharedKey(myPrivateKey, theirPublicKey)
  const result = secretDecrypt(sharedSecret, data, nonce)
  return result
}

export function anonEncrypt (theirPublicKey, message) {
  message = ensureBuffer(message)
  const X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, theirPublicKey)

  const ciphertext = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(ciphertext, message, X25519pk)
  return ciphertext
}

export function anonDecrypt (myKeys, ciphertext) {
  const X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  const X25519sk = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, myKeys.publicKey)
  sodium.crypto_sign_ed25519_sk_to_curve25519(X25519sk, myKeys.privateKey)

  const decrypted = Buffer.alloc(ciphertext.length - sodium.crypto_box_SEALBYTES)
  return sodium.crypto_box_seal_open(decrypted, ciphertext, X25519pk, X25519sk) && decrypted
}

export function secretEncrypt (secretKey, data, nonce, ad = Buffer.alloc(0)) {
  secretEncryptErrorHandler(arguments)
  let n
  data = ensureBuffer(data)
  if (!nonce) {
    n = Buffer.alloc(NONCEBYTES)
    sodium.randombytes_buf(n)
  } else {
    n = nonce
  }
  const ciphertext = Buffer.alloc(data.length + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, data, ad, null, n, secretKey)
  return !nonce ? Buffer.concat([n, ciphertext]) : ciphertext
}

export function secretDecrypt (secretKey, ciphertext, nonce, ad = Buffer.alloc(0)) {
  secretEncryptErrorHandler(arguments)
  if (!nonce) {
    nonce = ciphertext.subarray(0, NONCEBYTES)
    ciphertext = ciphertext.subarray(NONCEBYTES)
  }
  const output = Buffer.alloc(ciphertext.length - sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt(output, null, ciphertext, ad, nonce, secretKey)
  return output
}

export function sign (myKeys, data, salt) {
  data = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data
  const dataHash = hash(Buffer.from(data))
  const toSign = Buffer.concat([salt || Buffer.alloc(0), dataHash])

  const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, toSign, myKeys.privateKey)

  return signature
}

export function verify (publicKey, data, signature, salt) {
  data = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data

  const dataHash = hash(Buffer.from(data))
  const toVerify = Buffer.concat([salt || Buffer.alloc(0), dataHash])

  return sodium.crypto_sign_verify_detached(signature, toVerify, publicKey)
}

export function packMessage (message, recipientPublicKeys, senderKeys, nonRepubiable = false) {
  message = typeof message === 'object' && !Buffer.isBuffer(message) && message !== null ? canonicalize(message) : message
  const cek = randomBytes(RANDOMBYTES)
  const nonce = randomBytes(NONCEBYTES)

  const recipients = recipientPublicKeys.map((recipientPublicKey) => {
    recipientPublicKey = recipientPublicKey.publicKey ? recipientPublicKey.publicKey : recipientPublicKey
    const cekNonce = randomBytes(NONCEBYTES)
    const encryptedKey = senderKeys
      ? this.authEncrypt(recipientPublicKey, senderKeys.privateKey, cek, cekNonce)
      : this.anonEncrypt(recipientPublicKey, cek)

    let sender = null

    if (senderKeys) {
      if (!nonRepubiable) {
        sender = encode(this.anonEncrypt(
          recipientPublicKey,
          Buffer.from(senderKeys.publicKey)
        ))
      } else {
        const publicKey = senderKeys.publicKey
        sender = encode(this.anonEncrypt(
          recipientPublicKey,
          Buffer.from(publicKey)
        ))
      }
      return {
        encrypted_key: encode(encryptedKey),
        header: {
          kid: encode(recipientPublicKey),
          sender,
          iv: encode(cekNonce)
        }
      }
    } else {
      return {
        header: {
          kid: encode(recipientPublicKey)
        },
        encrypted_key: encode(encryptedKey)
      }
    }
  })

  const protectedencoded = encode(Buffer.from(canonicalize({
    enc: CIPHERALG,
    typ: `${PROTOCOL}/${VERSION}`,
    alg: senderKeys ? 'Authcrypt' : 'Anoncrypt',
    recipients
  })))

  const ciphertext = this.secretEncrypt(
    cek,
    message,
    nonce,
    Buffer.from(protectedencoded))
  const result = {
    protected: protectedencoded,
    ciphertext: encode(ciphertext.slice(AUTHTAGLENGTH, ciphertext.length)),
    iv: encode(nonce),
    tag: encode(ciphertext.slice(0, AUTHTAGLENGTH))
  }

  if (nonRepubiable) {
    const signature = this.sign(senderKeys, message, nonce)
    result.signature = encode(signature)
  }

  sodium.sodium_memzero(cek)
  sodium.sodium_memzero(nonce)
  return result
}

export function unpackMessage (packed, recipientKeys) {
  let protectedParsed

  try {
    protectedParsed = JSON.parse(decode(packed.protected))
  } catch (error) {
    return false
  }

  if (protectedParsed.typ !== `FAYTHE/${VERSION}`) return false
  let decrypted = false
  let verified = false
  protectedParsed.recipients.forEach((recipient) => {
    if (recipient.header.kid === encode(recipientKeys.publicKey)) {
      if (protectedParsed.alg === 'Authcrypt') {
        const senderPublicKey = this.anonDecrypt(
          recipientKeys,
          decode(recipient.header.sender))

        const slicedPublicKey = senderPublicKey.subarray(0, PUBLICKEYBYTES)

        const cek = this.authDecrypt(
          slicedPublicKey,
          recipientKeys.privateKey,
          decode(recipient.encrypted_key),
          decode(recipient.header.iv))
        decrypted = this.secretDecrypt(
          cek,
          Buffer.concat([decode(packed.tag), decode(packed.ciphertext)]),
          decode(packed.iv),
          Buffer.from(packed.protected))

        if (packed.signature) {
          try {
            verified = this.verify(senderPublicKey, decrypted, decode(packed.signature), decode(packed.iv))
          } catch (error) {
            decrypted = false
          }
        }
        sodium.sodium_memzero(cek)
      }

      if (protectedParsed.alg === 'Anoncrypt') {
        const cek = this.anonDecrypt(
          recipientKeys,
          decode(recipient.encrypted_key))

        decrypted = this.secretDecrypt(
          cek,
          Buffer.concat([decode(packed.tag), decode(packed.ciphertext)]),
          decode(packed.iv),
          Buffer.from(packed.protected))

        sodium.sodium_memzero(cek)
      }
    }
  })
  return packed.signature ? verified ? decrypted : false : decrypted
}
