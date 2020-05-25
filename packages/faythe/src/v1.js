
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
export const PUBLICKEYBYTES = 44
export const PRIVATEKEYBYTES = 48
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
  if (!args[0] || args[0].type !== 'public') throw new TypeError('First argument must be a publicKeyObject')
  if (!args[1] || args[1].type !== 'private') throw new TypeError('Second argument must be a privateKeyObject')
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
    const kp = x25519.generateKeyPair()
    return {
      publicKey: { key: Buffer.concat([X25519PKASN1, Buffer.from(kp.publicKey)]), type: 'public', export: function () { return this.key } },
      privateKey: { key: Buffer.concat([X25519SKASN1, Buffer.from(kp.secretKey)]), type: 'private', export: function () { return this.key } }
    }
  } else {
    return crypto.generateKeyPairSync(ENCRYPTIONKEYTYPE)
  }
}

export function generateVerificationKeyPair () {
  if (process.browser) {
    const kp = ed25519.generateKeyPair()
    return {
      publicKey: { key: Buffer.concat([ED25519PKASN1, Buffer.from(kp.publicKey)]), type: 'public', export: function () { return this.key } },
      privateKey: { key: Buffer.concat([ED25519SKASN1, Buffer.from(kp.secretKey).slice(0, 32)]), export: function () { return this.key } }
    }
  } else {
    return crypto.generateKeyPairSync(VERIFICATIONKEYTYPE)
  }
}

export function generateIdentity () {
  const keyPair = this.generateKeyPair()
  const verKeyPair = this.generateVerificationKeyPair()
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    verPublicKey: verKeyPair.publicKey,
    verPrivateKey: verKeyPair.privateKey
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

export function derive (namespace, key, name) {
  const h = new BLAKE2b(RANDOMBYTES, { key })
  h.update(Buffer.from(Buffer.byteLength(namespace, 'ascii') + '\n' + namespace, 'ascii'))
  h.update(Buffer.isBuffer(name) ? name : Buffer.from(name))
  const digest = h.digest()
  h.clean()
  return Buffer.from(digest)
}

export function precomputeSharedKey (myPrivateKey, theirPublicKey) {
  if (process.browser) {
    return Buffer.from(
      x25519.sharedKey(
        myPrivateKey.key.slice(X25519SKASN1.length, myPrivateKey.export().length),
        theirPublicKey.key.slice(X25519PKASN1.length, theirPublicKey.export().length)
      ))
  } else {
    return crypto.diffieHellman({
      privateKey: myPrivateKey,
      publicKey: theirPublicKey
    })
  }
}

export function authEncrypt (theirPublicKeyObject, myPrivateKeyObject, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedKey = this.precomputeSharedKey(myPrivateKeyObject, theirPublicKeyObject)
  const result = this.secretEncrypt(sharedKey, data, nonce)
  return result
}

export function authDecrypt (theirPublicKeyObject, myPrivateKeyObject, data, nonce) {
  authEncryptErrorHandler(arguments)
  const sharedKey = precomputeSharedKey(myPrivateKeyObject, theirPublicKeyObject)
  const result = this.secretDecrypt(sharedKey, data, nonce)
  return result
}

export function anonEncrypt (theirPublicKeyObject, message) {
  const ephkp = this.generateKeyPair()

  const ephPublicKeyBuffer = Buffer.from(toDerKey(ephkp.publicKey))

  const nonce = hash(Buffer.concat([
    ephPublicKeyBuffer,
    Buffer.from(toDerKey(theirPublicKeyObject))
  ])).slice(0, NONCEBYTES)

  const ciphertext = Buffer.concat([
    ephPublicKeyBuffer,
    this.authEncrypt(theirPublicKeyObject, ephkp.privateKey, message, nonce)
  ])

  ephPublicKeyBuffer.fill(0)
  nonce.fill(0)
  return Buffer.from(ciphertext)
}

export function anonDecrypt (myKeys, ciphertext) {
  let ephPublicKey
  if (process.browser) {
    ephPublicKey = {
      key: ciphertext.slice(0, PUBLICKEYBYTES),
      type: 'public',
      export: function () { return this.key }
    }
  } else {
    ephPublicKey = crypto.createPublicKey({
      key: ciphertext.slice(0, PUBLICKEYBYTES),
      type: EXPORTPUBLICKEYTYPE,
      format: EXPORTKEYFORMAT
    })
  }

  const nonce = hash(Buffer.concat([
    ciphertext.slice(0, PUBLICKEYBYTES),
    toDerKey(myKeys.publicKey)
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
    signature = ed25519.sign(
      Buffer.concat([
        myKeys.verPrivateKey.key.slice(SKASN1LENGTH, PRIVATEKEYBYTES),
        myKeys.verPublicKey.key.slice(PKASN1LENGTH, PUBLICKEYBYTES)
      ])
      , toSign)
  } else {
    signature = crypto.sign(null, toSign, myKeys.verPrivateKey)
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
    verified = ed25519.verify(publicKeyObject.export({
      type: EXPORTPUBLICKEYTYPE,
      format: EXPORTKEYFORMAT
    }).slice(PKASN1LENGTH, PUBLICKEYBYTES), toVerify, signature)
  } else {
    verified = crypto.verify(null, toVerify, publicKeyObject, signature)
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
          Buffer.from(toDerKey(senderKeysObject.publicKey))
        )).toString()
      } else {
        if (!senderKeysObject.verPublicKey) throw new Error("Non repudiable message require sender's verification key")
        const publicKey = toDerKey(senderKeysObject.publicKey)

        const verPublicKey = toDerKey(senderKeysObject.verPublicKey)
        sender = encode(this.anonEncrypt(
          recipientPublicKeyObject,
          Buffer.concat([Buffer.from(publicKey), Buffer.from(verPublicKey)])
        )).toString()
      }
      return {
        encrypted_key: encode(encryptedKey).toString(),
        header: {
          kid: encode(toDerKey(recipientPublicKeyObject)).toString(),
          sender,
          iv: encode(cekNonce).toString()
        }
      }
    } else {
      return {
        header: {
          kid: encode(toDerKey(recipientPublicKeyObject)).toString()
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
    result.signature = encode(Buffer.from(signature)).toString()
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
    if (recipient.header.kid === encode(toDerKey(recipientKeysObject.publicKey)).toString()) {
      if (protectedParsed.alg === 'auth') {
        const senderPublicKey = this.anonDecrypt(
          recipientKeysObject,
          decode(recipient.header.sender))

        const slicedPublicKey = senderPublicKey.slice(0, PUBLICKEYBYTES)

        let senderPublicKeyObject
        if (process.browser) {
          senderPublicKeyObject = {
            key: slicedPublicKey,
            type: 'public',
            export: function () { return this.key }
          }
        } else {
          senderPublicKeyObject = crypto.createPublicKey({
            key: slicedPublicKey,
            type: EXPORTPUBLICKEYTYPE,
            format: EXPORTKEYFORMAT
          })
        }
        const cek = this.authDecrypt(
          senderPublicKeyObject,
          recipientKeysObject.privateKey,
          decode(recipient.encrypted_key),
          decode(recipient.header.iv))
        decrypted = this.secretDecrypt(
          cek,
          Buffer.concat([decode(packed.tag), decode(packed.ciphertext)]),
          decode(packed.iv),
          Buffer.from(packed.protected))
        if (packed.signature) {
          const senderVerPublicKey = senderPublicKey.slice(PUBLICKEYBYTES, PUBLICKEYBYTES * 2)
          let senderVerPublicKeyObject
          if (process.browser) {
            senderVerPublicKeyObject = {
              key: senderVerPublicKey,
              type: 'public',
              export: function () { return this.key }
            }
          } else {
            senderVerPublicKeyObject = crypto.createPublicKey({
              key: senderVerPublicKey,
              type: EXPORTPUBLICKEYTYPE,
              format: EXPORTKEYFORMAT
            })
          }
          try {
            const verified = this.verify(senderVerPublicKeyObject, decrypted, decode(packed.signature))
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

export function compact (packedMessage) {
  packedMessage = { ...packedMessage }
  const p = JSON.parse(decode(packedMessage.protected).toString())
  const op = p.alg
  const signature = packedMessage.signature || null

  delete packedMessage.protected

  const payload = Buffer.from(serialize({
    ...packedMessage,
    recipients: p.recipients
  }))

  return signature
    ? `v${VERSION}.${op}.${multibase.encode(ENCODER, payload)}.${signature}`
    : `v${VERSION}.${op}.${multibase.encode(ENCODER, payload)}`
}

export function uncompact (compressed) {
  const parts = compressed.split('.')
  const version = parts[0]
  const op = parts[1]
  const payload = parts[2]
  const signature = parts[3] || null
  const deserialized = deserialize(Buffer.from(decode(payload)))

  const decoded = {
    protected: encode(JSON.stringify({
      enc: CIPHERALGID,
      typ: `FAYTHE/${version}`,
      alg: op,
      recipients: deserialized.recipients
    })).toString(),
    ...deserialized
  }

  if (signature) decoded.signature = signature
  delete decoded.recipients
  return decoded
}

export function exportKeyPair (keyPairObject, options = {}) {
  const format = options.format || EXPORTKEYFORMAT
  // const passphrase = options.passphrase || ''
  return {
    publicKey: keyPairObject.publicKey.export({
      type: EXPORTPUBLICKEYTYPE,
      format
    }),
    privateKey: keyPairObject.privateKey.export({
      type: EXPORTPRIVATEKEYTYPE,
      format
      // cipher: passphrase ? EXPORTCIPHER : undefined,
      // passphrase: passphrase
    })
  }
}

export function toDerKey (keyObject) {
  if (keyObject.type === 'public') {
    return keyObject.export({
      type: EXPORTPUBLICKEYTYPE,
      format: EXPORTKEYFORMAT
    })
  }
  if (keyObject.type === 'private') {
    return keyObject.export({
      type: EXPORTPRIVATEKEYTYPE,
      format: EXPORTKEYFORMAT
    })
  }
}

export function importKeyPair (keyPair, options = {}) {
  const format = options.format || EXPORTKEYFORMAT
  // const passphrase = options.passphrase || ''
  if (process.browser) {
    return {
      publicKey: { key: Buffer.concat([ED25519PKASN1, Buffer.from(keyPair.publicKey)]), type: 'public', export: function () { return this.key } },
      privateKey: { key: Buffer.concat([ED25519SKASN1, Buffer.from(keyPair.privateKey).slice(0, 32)]), type: 'private', export: function () { return this.key } }
    }
  } else {
    return {
      publicKey: crypto.createPublicKey({
        key: keyPair.publicKey,
        type: EXPORTPUBLICKEYTYPE,
        format
      }),
      privateKey: crypto.createPrivateKey({
        key: keyPair.privateKey,
        type: EXPORTPRIVATEKEYTYPE,
        format
        // cipher: EXPORTCIPHER,
        // passphrase
      })
    }
  }
}
