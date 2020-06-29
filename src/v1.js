
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'
import { convertPublicKeyToX25519, convertSecretKeyToX25519 } from '@stablelib/ed25519'
import { NewHope } from '@stablelib/newhope'
import * as cbor from '@stablelib/cbor'
import { Buffer } from 'buffer'
import multibase from 'multibase'
import canonicalize from 'canonicalize'
import sodium from 'sodium-universal'
import sha512 from 'sha512-wasm' // browser wait for wasm to load

export const PROTOCOL = 'FAYTHE'
export const VERSION = '1'
export const RANDOMBYTES = 32
export const NONCEBYTES = 24
export const HASHBYTES = 32
export const PUBLICKEYBYTES = 32
export const PRIVATEKEYBYTES = 64 // Concatenated publicKey
export const ENCRYPTEDPRIVATEKEYBYTES = 158
export const SHAREDKEYBYTES = 32
export const SALTBYTES = 12
export const AUTHTAGLENGTH = 16
export const ENCODER = 'base64url'
export const SERIALIZER = 'cbor'
export const ENCRYPTIONKEYTYPE = 'x25519'
export const VERIFICATIONKEYTYPE = 'ed25519'
export const CIPHERALG = 'xchacha20-poly1305'
export const CIPHERALGID = 'XC20P'
export const HASHALG = 'BLAKE2b'

const INCEPTIONKEY = Symbol('inceptionkey')

const encode = (buffer) => multibase.encode(ENCODER, buffer)
const decode = (bufOrString) => multibase.decode(bufOrString)

const serialize = cbor.encode
const deserialize = cbor.decode

export { canonicalize, encode, decode, serialize, deserialize }

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

export class Identity {
  constructor (masterkey, name, namespace) {
    this.name = name || Buffer.alloc(PUBLICKEYBYTES, 'identity')
    this.namespace = namespace || Buffer.alloc(PUBLICKEYBYTES, 'faythe')
    this[INCEPTIONKEY] = masterkey ? Buffer.alloc(
      masterkey.length < RANDOMBYTES ? RANDOMBYTES : masterkey.length,
      Buffer.isBuffer(masterkey) ? masterkey : Buffer.from(masterkey))
      : randomBytes(RANDOMBYTES)
    const seed = derive(this[INCEPTIONKEY], this.name, this.namespace)
    this[INCEPTIONKEY].fill(0)
    const keyPair = generateKeyPair()
    seed.fill(0)
    this.verPublicKey = Buffer.from(keyPair.publicKey)
    this.verPrivateKey = Buffer.from(keyPair.privateKey) // 64 bytes
    this.encPublicKey = Buffer.from(convertPublicKeyToX25519(this.publicKey))
    this.encPrivateKey = Buffer.from(convertSecretKeyToX25519(this.privateKey))
    this.offers = new Map()
    this.sharedKeys = new Map()
  }

  offer (id) {
    const nh = new NewHope()
    const offer = nh.offer()
    this.offers.set(id, nh.saveState())
    return offer
  }

  accept (offerMsg, id) {
    const nh = new NewHope()
    const accept = nh.accept(offerMsg)
    this.sharedKeys.set(id, nh.getSharedKey())
    return accept
  }

  finish (acceptMsg, id) {
    const nh = new NewHope()
    nh.restoreState(this.offers.get(id))
    nh.finish(acceptMsg)
    this.sharedKeys.set(id, nh.getSharedKey())
    this.offers.delete(id)
    return nh.getSharedKey()
  }

  get publicKey () {
    return this.verPublicKey
  }

  get privateKey () {
    return this.verPrivateKey
  }

  toJson () {
    return {
      id: encode(this.publicKey).toString().substring(1, 8),
      type: 'Ed25519VerificationKey2018',
      controller: '#id',
      publicKeyMultiBase: encode(this.publicKey).toString(),
      publicKeyBase64url: encode(this.publicKey).toString().substring(1),
      publicKeyBase64: this.publicKey.toString('base64'),
      publicKeyHex: this.publicKey.toString('hex'),
      publicKeyBase58: multibase.encode('base58btc', this.publicKey).toString().substring(1)
    }
  }
}

export async function ready (cb) {
  sha512.ready(() => {
    cb()
  })
}

export function generateKeyPair () {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return {
    publicKey: pk,
    privateKey: sk
  }
}

export function hash (data) {
  const b = Buffer.alloc(HASHBYTES)
  sodium.crypto_generichash(b, ensureBuffer(data))
  return b
}

export function derive (key, name, namespace) {
  const derived = Buffer.alloc(32)

  sodium.crypto_generichash_batch(derived, [
    Buffer.from(Buffer.byteLength(namespace, 'ascii') + '\n' + namespace, 'ascii'),
    Buffer.isBuffer(name) ? name : Buffer.from(name)
  ], key)

  return derived
}

export function precomputeSharedKey (myPrivateKey, theirPublicKey, client) {
  let X25519pk
  let X25519sk
  if (process.browser) {
    X25519pk = convertPublicKeyToX25519(theirPublicKey)
    X25519sk = convertSecretKeyToX25519(myPrivateKey)
  } else {
    X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
    X25519sk = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, theirPublicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(X25519sk, myPrivateKey)
  }

  const q = Buffer.alloc(sodium.crypto_scalarmult_BYTES)

  sodium.crypto_scalarmult(
    q,
    X25519sk,
    X25519pk
  )
  return !client
    ? hash(Buffer.concat([q, myPrivateKey.subarray(sodium.crypto_sign_PUBLICKEYBYTES), theirPublicKey]))
    : hash(Buffer.concat([q, theirPublicKey, myPrivateKey.subarray(sodium.crypto_sign_PUBLICKEYBYTES)]))
}

export function authEncrypt (theirPublicKey, myPrivateKey, data, nonce, client) {
  authEncryptErrorHandler(arguments)
  const sharedKey = this.precomputeSharedKey(myPrivateKey, theirPublicKey, client)
  const result = this.secretEncrypt(sharedKey, data, nonce)
  return result
}

export function authDecrypt (theirPublicKey, myPrivateKey, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedKey = precomputeSharedKey(myPrivateKey, theirPublicKey)
  const result = this.secretDecrypt(sharedKey, data, nonce)
  return result
}

export function anonEncrypt (theirPublicKey, message) {
  const ephkp = this.generateKeyPair()

  const ephPublicKeyBuffer = Buffer.from(ephkp.publicKey)

  const nonce = hash(Buffer.concat([
    ephPublicKeyBuffer,
    Buffer.from(theirPublicKey)
  ])).subarray(0, NONCEBYTES)

  const ciphertext = Buffer.concat([
    ephPublicKeyBuffer,
    this.authEncrypt(theirPublicKey, ephkp.privateKey, message, nonce, true)
  ])

  ephPublicKeyBuffer.fill(0)
  nonce.fill(0)
  return Buffer.from(ciphertext)
}

export function anonDecrypt (myKeys, ciphertext) {
  const ephPublicKey = ciphertext.subarray(0, PUBLICKEYBYTES)

  const nonce = hash(Buffer.concat([
    ciphertext.slice(0, PUBLICKEYBYTES),
    myKeys.publicKey
  ])).slice(0, NONCEBYTES)

  const decrypted = this.authDecrypt(
    ephPublicKey,
    myKeys.privateKey,
    ciphertext.slice(PUBLICKEYBYTES, ciphertext.length),
    nonce)

  nonce.fill(0)
  return decrypted
}

export function secretEncrypt (sharedSecret, data, nonce, AAD = Buffer.alloc(0)) {
  secretEncryptErrorHandler(arguments)

  const aad = Buffer.concat([Buffer.from(VERSION), AAD])

  const cipher = new XChaCha20Poly1305(sharedSecret)
  if (!nonce) {
    nonce = randomBytes(NONCEBYTES)
    const ciphertext = cipher.seal(nonce, Buffer.from(data), aad)
    return Buffer.concat([nonce, Buffer.from(ciphertext)])
  } else {
    const ciphertext = cipher.seal(nonce, Buffer.from(data), aad)
    return Buffer.from(ciphertext)
  }
}

export function secretDecrypt (sharedSecret, data, nonce, AAD = Buffer.alloc(0)) {
  secretEncryptErrorHandler(arguments)
  const aad = Buffer.concat([Buffer.from(VERSION), AAD])

  const decipher = new XChaCha20Poly1305(sharedSecret)
  if (!nonce) {
    const decrypted = decipher.open(data.slice(0, NONCEBYTES), data.slice(NONCEBYTES, data.length), aad)
    return Buffer.from(decrypted)
  } else {
    const decrypted = decipher.open(nonce, data, aad)
    return Buffer.from(decrypted)
  }
}

export function sign (myKeys, data, salt) {
  data = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data
  const dataHash = hash(Buffer.from(data))
  const toSign = salt
    ? Buffer.concat([salt, dataHash])
    : dataHash

  const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, toSign, myKeys.privateKey)

  return signature
}

export function verify (publicKey, data, signature, salt) {
  data = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data

  const dataHash = hash(Buffer.from(data))
  const toVerify = salt
    ? Buffer.concat([salt, dataHash])
    : dataHash

  return sodium.crypto_sign_verify_detached(signature, ensureBuffer(toVerify), publicKey)
}

export function packMessage (message, recipientPublicKeys, senderKeys, nonRepubiable = false) {
  message = typeof message === 'object' && !Buffer.isBuffer(message) && message !== null ? canonicalize(message) : message
  const cek = randomBytes(RANDOMBYTES)
  const nonce = randomBytes(NONCEBYTES)

  const recipients = recipientPublicKeys.map((recipientPublicKey) => {
    recipientPublicKey = recipientPublicKey.publicKey ? recipientPublicKey.publicKey : recipientPublicKey
    const cekNonce = randomBytes(NONCEBYTES)
    const encryptedKey = senderKeys
      ? this.authEncrypt(recipientPublicKey, senderKeys.privateKey, cek, cekNonce, true)
      : this.anonEncrypt(recipientPublicKey, cek)

    let sender = null

    if (senderKeys) {
      if (!nonRepubiable) {
        sender = encode(this.anonEncrypt(
          recipientPublicKey,
          Buffer.from(senderKeys.publicKey)
        )).toString()
      } else {
        const publicKey = senderKeys.publicKey
        sender = encode(this.anonEncrypt(
          recipientPublicKey,
          Buffer.from(publicKey)
        )).toString()
      }
      return {
        encrypted_key: encode(encryptedKey).toString(),
        header: {
          kid: encode(recipientPublicKey).toString(),
          sender,
          iv: encode(cekNonce).toString()
        }
      }
    } else {
      return {
        header: {
          kid: encode(recipientPublicKey).toString()
        },
        encrypted_key: encode(encryptedKey).toString()
      }
    }
  })

  const protectedencoded = encode(Buffer.from(canonicalize({
    enc: CIPHERALGID,
    typ: `FAYTHE/${VERSION}`,
    alg: senderKeys ? 'auth' : 'anon',
    recipients
  }))).toString()

  const ciphertext = this.secretEncrypt(
    cek,
    message,
    nonce,
    Buffer.from(protectedencoded))

  const result = {
    protected: protectedencoded,
    ciphertext: encode(ciphertext.slice(AUTHTAGLENGTH, ciphertext.length)).toString(),
    iv: encode(nonce).toString(),
    tag: encode(ciphertext.slice(0, AUTHTAGLENGTH)).toString()
  }

  if (nonRepubiable) {
    const signature = this.sign(senderKeys, message)
    result.signature = encode(signature).toString()
  }

  cek.fill(0)
  nonce.fill(0)
  return result
}

export function unpackMessage (packed, recipientKeys) {
  let protectedParsed

  try {
    protectedParsed = JSON.parse(decode(packed.protected).toString())
  } catch (error) {
    return false
  }

  if (/** protectedParsed.enc !== CIPHERALGID || */ protectedParsed.typ !== `FAYTHE/${VERSION}`) return false
  let decrypted = false
  let verified = false
  protectedParsed.recipients.forEach((recipient) => {
    if (recipient.header.kid === encode(recipientKeys.publicKey).toString()) {
      if (protectedParsed.alg === 'auth') {
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
            verified = this.verify(senderPublicKey, decrypted, decode(packed.signature))
          } catch (error) {
            decrypted = false
          }
        }
        cek.fill(0)
      }

      if (protectedParsed.alg === 'anon') {
        const cek = this.anonDecrypt(
          recipientKeys,
          decode(recipient.encrypted_key))

        decrypted = this.secretDecrypt(
          cek,
          Buffer.concat([decode(packed.tag), decode(packed.ciphertext)]),
          decode(packed.iv),
          Buffer.from(packed.protected))

        cek.fill(0)
      }
    }
  })
  return packed.signature ? verified ? decrypted : false : decrypted
}
