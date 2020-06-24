
import crypto from 'crypto'
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305'
import { hash as blake2b, BLAKE2b } from '@stablelib/blake2b'
import * as ed25519 from '@stablelib/ed25519'
import * as x25519 from '@stablelib/x25519'
import * as random from '@stablelib/random'
import * as cbor from '@stablelib/cbor'
import { Buffer } from 'buffer'
import multibase from 'multibase'
import canonicalize from 'canonicalize'

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
export const HASHALG = 'BLAKE2b512'
export const EXPORTCIPHER = 'aes-256-cbc'
export const EXPORTKEYFORMAT = 'der'
export const EXPORTPUBLICKEYTYPE = 'spki'
export const EXPORTPRIVATEKEYTYPE = 'pkcs8'
export const ED25519PKASN1 = Buffer.from('302a300506032b6570032100', 'hex')
export const ED25519SKASN1 = Buffer.from('302e020100300506032b657004220420', 'hex')
export const X25519PKASN1 = Buffer.from('302a300506032b656e032100', 'hex')
export const X25519SKASN1 = Buffer.from('302e020100300506032b656e04220420', 'hex')
export const PKASN1LENGTH = 12
export const SKASN1LENGTH = 16

const INCEPTIONKEY = Symbol('inceptionkey')

const encode = (buffer) => multibase.encode(ENCODER, buffer)
const decode = (bufOrString) => multibase.decode(bufOrString)

const serialize = cbor.encode
const deserialize = cbor.decode

export { canonicalize, encode, decode, serialize, deserialize }

export function randomBytes (bytes) {
  if (process.browser) {
    return Buffer.from(random.randomBytes(bytes))
  } else {
    return crypto.randomBytes(bytes)
  }
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

export function generateKeyPair () {
  if (process.browser) {
    const kp = ed25519.generateKeyPair()
    return {
      publicKey: Buffer.from(kp.publicKey),
      privateKey: Buffer.from(kp.secretKey)
    }
  } else {
    const kp = crypto.generateKeyPairSync(VERIFICATIONKEYTYPE)
    return {
      publicKey: keyObjectToRawKey(kp.publicKey),
      privateKey: Buffer.concat([keyObjectToRawKey(kp.privateKey), keyObjectToRawKey(kp.publicKey)])
    }
  }
}

export class Identity {
  constructor (masterkey, namespace, name) {
    this.namespace = namespace || 'faythe'
    this.name = name || 'identity'
    this[INCEPTIONKEY] = masterkey ? Buffer.alloc(masterkey.length < RANDOMBYTES
      ? RANDOMBYTES
      : masterkey.length, Buffer.isBuffer(masterkey)
      ? masterkey : Buffer.from(masterkey))
      : randomBytes(RANDOMBYTES)
    const seed = derive(this[INCEPTIONKEY], this.namespace, this.name, 'register')
    this[INCEPTIONKEY].fill(0)
    const keyPair = ed25519.generateKeyPairFromSeed(seed)
    seed.fill(0)
    this.verPublicKey = Buffer.from(keyPair.publicKey)
    this.verPrivateKey = Buffer.from(keyPair.secretKey)
    this.encPublicKey = Buffer.from(ed25519.convertPublicKeyToX25519(this.publicKey))
    this.encPrivateKey = Buffer.from(ed25519.convertSecretKeyToX25519(this.privateKey))
  }

  get publicKey () {
    return this.verPublicKey
  }

  get privateKey () {
    return this.verPrivateKey
  }

  link (identity) {
    const theirPublicKey = ed25519.convertPublicKeyToX25519(identity.publicKey || identity)
    const sharedKey = hash(x25519.sharedKey(this.encPrivateKey, theirPublicKey, true))
    return new Identity(sharedKey, this.namespace, identity.name || 'link')
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

export function hash (data) {
  if (process.browser) {
    return Buffer.from(blake2b(data)).slice(0, HASHBYTES)
  } else {
    const hasher = crypto.createHash(HASHALG)
    hasher.update(data)
    return hasher.digest().slice(0, HASHBYTES)
  }
}

export function derive (namespace, key, name, personalization) {
  const h = new BLAKE2b(RANDOMBYTES, { key, personalization: Buffer.alloc(16, Buffer.isBuffer(personalization) ? personalization : Buffer.from(personalization)) })
  h.update(Buffer.isBuffer(namespace) ? namespace : Buffer.from(namespace))
  h.update(Buffer.isBuffer(name) ? name : Buffer.from(name))
  const digest = h.digest()
  h.clean()
  return Buffer.from(digest)
}

export function precomputeSharedKey (myPrivateKey, theirPublicKey) {
  if (process.browser) {
    return Buffer.from(
      x25519.sharedKey(
        ed25519.convertSecretKeyToX25519(myPrivateKey),
        ed25519.convertPublicKeyToX25519(theirPublicKey)
      ))
  } else {
    return crypto.diffieHellman({
      privateKey: rawKeyToKeyObject(ed25519.convertSecretKeyToX25519(myPrivateKey), 'private'),
      publicKey: rawKeyToKeyObject(ed25519.convertPublicKeyToX25519(theirPublicKey), 'public')
    })
  }
}

export function authEncrypt (theirPublicKey, myPrivateKey, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedKey = this.precomputeSharedKey(myPrivateKey, theirPublicKey)

  const result = this.secretEncrypt(sharedKey, data, nonce)
  return result
}

export function authDecrypt (theirPublicKeyObject, myPrivateKeyObject, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedKey = precomputeSharedKey(myPrivateKeyObject, theirPublicKeyObject)
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
    this.authEncrypt(theirPublicKey, ephkp.privateKey, message, nonce)
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
  let signature
  if (process.browser) {
    signature = Buffer.from(ed25519.sign(
      myKeys.privateKey,
      toSign))
  } else {
    signature = crypto.sign(null, toSign, rawKeyToKeyObject(myKeys.privateKey, 'private', 'verification'))
  }

  return signature
}

export function verify (publicKeyObject, data, signature, salt) {
  data = typeof data === 'object' && !Buffer.isBuffer(data) ? canonicalize(data) : data
  let verified
  const dataHash = hash(Buffer.from(data))
  const toVerify = salt
    ? Buffer.concat([salt, dataHash])
    : dataHash
  if (process.browser) {
    if (signature.length !== ed25519.SIGNATURE_LENGTH) return false
    verified = ed25519.verify(publicKeyObject, toVerify, signature)
  } else {
    verified = crypto.verify(null, toVerify, rawKeyToKeyObject(publicKeyObject, 'public', 'verification'), signature)
  }

  return verified
}

export function packMessage (message, recipientsPublicKeysObject, senderKeysObject, nonRepubiable = false) {
  message = typeof message === 'object' && !Buffer.isBuffer(message) && message !== null ? canonicalize(message) : message
  const cek = randomBytes(RANDOMBYTES)
  const nonce = randomBytes(NONCEBYTES)

  const recipients = recipientsPublicKeysObject.map((recipientPublicKeyObject) => {
    const cekNonce = randomBytes(NONCEBYTES)
    const encryptedKey = senderKeysObject
      ? this.authEncrypt(recipientPublicKeyObject, senderKeysObject.privateKey, cek, cekNonce)
      : this.anonEncrypt(recipientPublicKeyObject, cek)

    let sender = null

    if (senderKeysObject) {
      if (!nonRepubiable) {
        sender = encode(this.anonEncrypt(
          recipientPublicKeyObject,
          Buffer.from(senderKeysObject.publicKey)
        )).toString()
      } else {
        const publicKey = senderKeysObject.publicKey
        sender = encode(this.anonEncrypt(
          recipientPublicKeyObject,
          Buffer.from(publicKey)
        )).toString()
      }
      return {
        encrypted_key: encode(encryptedKey).toString(),
        header: {
          kid: encode(recipientPublicKeyObject).toString(),
          sender,
          iv: encode(cekNonce).toString()
        }
      }
    } else {
      return {
        header: {
          kid: encode(recipientPublicKeyObject).toString()
        },
        encrypted_key: encode(encryptedKey).toString()
      }
    }
  })

  const protectedencoded = encode(Buffer.from(canonicalize({
    enc: CIPHERALGID,
    typ: `FAYTHE/${VERSION}`,
    alg: senderKeysObject ? 'auth' : 'anon',
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
    const signature = this.sign(senderKeysObject, message)
    result.signature = encode(signature).toString()
  }

  cek.fill(0)
  nonce.fill(0)
  return result
}

export function unpackMessage (packed, recipientKeysObject) {
  let protectedParsed

  try {
    protectedParsed = JSON.parse(decode(packed.protected).toString())
  } catch (error) {
    return false
  }

  if (/** protectedParsed.enc !== CIPHERALGID || */ protectedParsed.typ !== `FAYTHE/${VERSION}`) return false
  let decrypted = false

  protectedParsed.recipients.forEach((recipient) => {
    if (recipient.header.kid === encode(recipientKeysObject.publicKey).toString()) {
      if (protectedParsed.alg === 'auth') {
        const senderPublicKey = this.anonDecrypt(
          recipientKeysObject,
          decode(recipient.header.sender))

        const slicedPublicKey = senderPublicKey.subarray(0, PUBLICKEYBYTES)

        const cek = this.authDecrypt(
          slicedPublicKey,
          recipientKeysObject.privateKey,
          decode(recipient.encrypted_key),
          decode(recipient.header.iv))
        decrypted = this.secretDecrypt(
          cek,
          Buffer.concat([decode(packed.tag), decode(packed.ciphertext)]),
          decode(packed.iv),
          Buffer.from(packed.protected))
        if (packed.signature) {
          try {
            const verified = this.verify(senderPublicKey, decrypted, decode(packed.signature))
            if (!verified) decrypted = false
          } catch (error) {
            decrypted = false
          }
        }
        cek.fill(0)
      }

      if (protectedParsed.alg === 'anon') {
        const cek = this.anonDecrypt(
          recipientKeysObject,
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
  return decrypted
}

export function keyObjectToRawKey (keyObject) {
  if (keyObject.type === 'public') {
    return keyObject.export({
      type: EXPORTPUBLICKEYTYPE,
      format: EXPORTKEYFORMAT
    }).subarray(PKASN1LENGTH)
  }
  if (keyObject.type === 'private') {
    return keyObject.export({
      type: EXPORTPRIVATEKEYTYPE,
      format: EXPORTKEYFORMAT
    }).subarray(SKASN1LENGTH)
  }
}

export function rawKeyToKeyObject (key, type, use) {
  if (type === 'public') {
    return crypto.createPublicKey({
      key: Buffer.concat([use === 'verification' ? ED25519PKASN1 : X25519PKASN1, key]),
      type: EXPORTPUBLICKEYTYPE,
      format: EXPORTKEYFORMAT
    })
  }
  if (type === 'private') {
    return crypto.createPrivateKey({
      key: Buffer.concat([use === 'verification' ? ED25519SKASN1 : X25519SKASN1, key]),
      type: EXPORTPRIVATEKEYTYPE,
      format: EXPORTKEYFORMAT
    })
  }
}
