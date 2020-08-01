
import _libsodium from 'libsodium-wrappers' // pwhash, convert to curve25519
import sodium from 'sodium-universal'
import * as cbor from '@stablelib/cbor'
import { NewHope } from '@stablelib/newhope'
import { Buffer } from 'buffer'
import multibase from 'multibase'
import canonicalize from 'canonicalize'
import sha512 from 'sha512-wasm' // browser wait for wasm to load
import thunky from 'thunky/promise'

export const PROTOCOL = 'FAYTHE'
export const VERSION = '1'
export const RANDOMBYTES = 32
export const NONCEBYTES = 12
export const HASHBYTES = 32
export const PUBLICKEYBYTES = 32
export const PRIVATEKEYBYTES = 64 // Concatenated publicKey
export const SHAREDKEYBYTES = 32
export const SALTBYTES = 12
export const MIN_SEEDBYTES = 16
export const AUTHTAGLENGTH = 16
export const ENCODER = 'base64url'
export const SERIALIZER = 'cbor'
export const ENCRYPTIONKEYTYPE = 'x25519'
export const VERIFICATIONKEYTYPE = 'Ed25519VerificationKey2018'

export const CIPHERALG = 'Chacha20-Poly1305'
export const CIPHERALGID = 'C20P'
export const HASHALG = 'blake2b-256'

let libsodium
const MASTERKEY = Symbol('MASTERKEY')

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
  constructor (passphrase, idspace, name, rotation = 0, sensitive = false) {
    if (!passphrase) passphrase = randomBytes(MIN_SEEDBYTES)
    else passphrase = ensureBuffer(passphrase)
    this.seed = passphrase
    this.idspace = idspace ? ensureBuffer(idspace) : Buffer.alloc(RANDOMBYTES, 'local')
    this.name = name || 'identity'
    this.rotation = rotation
    const salt = hashBatch([this.idspace, ensureBuffer(this.name)], libsodium.crypto_pwhash_SALTBYTES) // 16 bytes

    const stretchedKey = pwhash(passphrase, salt, sensitive) // if sensitive is true, this can take few seconds...
    this._locked = false
    this[MASTERKEY] = deriveFromKey(stretchedKey, rotation, 'rotation') // 32 bytes

    const keyPair = this.keyPairFor(this.idspace)
    this.preRotatedKey = hash(this.keyPairFor(this.idspace, deriveFromKey(stretchedKey, rotation + 1, 'rotation')).publicKey)
    this.namespace = hashBatch([this.idspace, keyPair.publicKey])
    this.verPublicKey = Buffer.from(keyPair.publicKey)
    this.verPrivateKey = Buffer.from(keyPair.privateKey) // 64 bytes
  }

  keyPairFor (idspace, masterKey) {
    if (!this.locked) return generateKeyPair(derive(masterKey || this[MASTERKEY], idspace, this.name))
    else return null
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

  get locked () {
    return this._locked
  }

  lock () {
    sodium.sodium_memzero(this[MASTERKEY])
    sodium.sodium_memzero(this.seed)
    sodium.sodium_memzero(this.verPublicKey)
    sodium.sodium_memzero(this.verPrivateKey)
    this._locked = true
  }

  toJson () {
    return {
      id: encode(this.publicKey).toString().substring(1, 8),
      type: VERIFICATIONKEYTYPE,
      controller: '#id',
      publicKeyMultiBase: encode(this.publicKey).toString(),
      publicKeyBase64url: encode(this.publicKey).toString().substring(1),
      publicKeyBase64: this.publicKey.toString('base64'),
      publicKeyHex: this.publicKey.toString('hex'),
      publicKeyBase58: multibase.encode('base58btc', this.publicKey).toString().substring(1)
    }
  }

  static ready (cb) {
    return ready(cb)
  }
}

export async function ready (cb) {
  return thunky(await _ready(cb))
}

async function _ready (cb) {
  await _libsodium.ready
  libsodium = _libsodium
  return new Promise(resolve => {
    sha512.ready(() => {
      if (cb) cb()
      resolve()
    })
  })
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
  const b = Buffer.alloc(bytes || HASHBYTES)
  if (key) sodium.crypto_generichash(b, ensureBuffer(data), key)
  else sodium.crypto_generichash(b, ensureBuffer(data))
  return b
}

export function hashBatch (data, bytes, key) {
  const b = Buffer.alloc(bytes || HASHBYTES)
  data = data.map(d => ensureBuffer(d))
  if (key) sodium.crypto_generichash_batch(b, ensureBuffer(data), key)
  else sodium.crypto_generichash_batch(b, data)
  return b
}

export function pwhash (password, salt, sensitive) {
  return libsodium.crypto_pwhash(RANDOMBYTES, ensureBuffer(password), salt,
    sensitive ? libsodium.crypto_pwhash_OPSLIMIT_SENSITIVE : libsodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sensitive ? libsodium.crypto_pwhash_MEMLIMIT_SENSITIVE : libsodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    libsodium.crypto_pwhash_ALG_DEFAULT)
}

export function derive (key, namespace, name) {
  const derived = Buffer.alloc(RANDOMBYTES)
  sodium.crypto_generichash_batch(derived, [
    Buffer.from(Buffer.byteLength(namespace, 'ascii') + '\n' + namespace, 'ascii'),
    ensureBuffer(name)
  ], key)

  return derived
}

export function deriveFromKey (key, int, ctx) {
  const context = Buffer.alloc(sodium.crypto_kdf_CONTEXTBYTES, ensureBuffer(ctx))
  const derived = Buffer.alloc(RANDOMBYTES)
  sodium.crypto_kdf_derive_from_key(derived, int, context, key)
  return derived
}

export function precomputeSharedKey (myPrivateKey, theirPublicKey, initiator) {
  let X25519pk
  let X25519sk
  if (process.browser) {
    X25519pk = libsodium.crypto_sign_ed25519_pk_to_curve25519(theirPublicKey)
    X25519sk = libsodium.crypto_sign_ed25519_sk_to_curve25519(myPrivateKey)
  } else {
    X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
    X25519sk = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, theirPublicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(X25519sk, myPrivateKey)
  }

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
  let X25519pk
  if (process.browser) {
    X25519pk = libsodium.crypto_sign_ed25519_pk_to_curve25519(theirPublicKey)
  } else {
    X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, theirPublicKey)
  }
  const ciphertext = Buffer.alloc(message.length + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(ciphertext, message, X25519pk)
  return ciphertext
}

export function anonDecrypt (myKeys, ciphertext) {
  let X25519pk
  let X25519sk
  if (process.browser) {
    X25519pk = libsodium.crypto_sign_ed25519_pk_to_curve25519(myKeys.publicKey)
    X25519sk = libsodium.crypto_sign_ed25519_sk_to_curve25519(myKeys.privateKey)
  } else {
    X25519pk = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
    X25519sk = Buffer.alloc(sodium.crypto_scalarmult_SCALARBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(X25519pk, myKeys.publicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(X25519sk, myKeys.privateKey)
  }
  const decrypted = Buffer.alloc(ciphertext.length - sodium.crypto_box_SEALBYTES)
  return sodium.crypto_box_seal_open(decrypted, ciphertext, X25519pk, X25519sk) && decrypted
}

export function secretEncrypt (secretKey, message, nonce, ad = Buffer.alloc(0)) {
  secretEncryptErrorHandler(arguments)
  let n
  message = ensureBuffer(message)
  if (!nonce) {
    n = Buffer.alloc(NONCEBYTES)
    sodium.randombytes_buf(n)
  } else {
    n = nonce
  }
  const ciphertext = Buffer.alloc(message.length + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, message, ad, null, n, secretKey)
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
      ? this.authEncrypt(recipientPublicKey, senderKeys.privateKey, cek, cekNonce)
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
    typ: `${PROTOCOL}/${VERSION}`,
    alg: senderKeys ? 'Authcrypt' : 'Anoncrypt',
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

  sodium.sodium_memzero(cek)
  sodium.sodium_memzero(nonce)
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
            verified = this.verify(senderPublicKey, decrypted, decode(packed.signature))
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
