
const faythe = require('..').v1

const BYTES = 64
const seed = Buffer.from(faythe.randomBytes(BYTES))

const lengths = {
  dataBytes: 32,
  padLength: 1,
  codeLength: 1,
  prefixBase64: 44,
  prefixBytes: 33
}

const objectMap = (obj, fn) =>
  Object.fromEntries(
    Object.entries(obj).map(
      ([k, v], i) => [k, fn(v, k, i)]
    )
  )

const derivationCodes = {
  A: {
    description: 'Non-transferable prefix using Ed25519 public signing verification key. Basic derivation.',
    ...lengths
  },
  B: {
    description: 'X25519 public encryption key. May be converted from Ed25519 public signing verification key',
    ...lengths
  },
  C: {
    description: 'Ed25519 public signing verification key. Basic derivation.',
    ...lengths
  },
  D: {
    description: 'Blake3-256 Digest. Self-addressing derivation.',
    ...lengths
  },
  E: {
    description: 'Blake2b-256 Digest. Self-addressing derivation.',
    ...lengths
  },
  F: {
    description: 'Blake2s-256 Digest. Self-addressing derivation.',
    ...lengths
  },
  G: {
    description: 'Non-transferable prefix using ECDSA secp256k1 public singing verification key. Basic derivation.',
    ...lengths
  },
  H: {
    description: 'ECDSA secp256k1 public signing verification key. Basic derivation.',
    ...lengths
  },
  I: {
    description: 'SHA3-256 Digest. Self-addressing derivation.',
    ...lengths
  },
  J: {
    description: 'SHA2-256 Digest. Self-addressing derivation.',
    ...lengths
  },
  0: {
    A: {
      description: 'Ed25519 signature. Self-signing derivation',
      ...objectMap(lengths, v => 2 * v)
    },
    B: {
      description: 'ECDSA secp256k1 signature. Self-signing derivation',
      ...objectMap(lengths, v => 2 * v)
    },
    C: {
      description: 'Blake3-512 Digest. Self-addressing derivation.',
      ...objectMap(lengths, v => 2 * v)
    },
    D: {
      description: 'SHA3-512 Digest. Self-addressing derivation.',
      ...objectMap(lengths, v => 2 * v)
    },
    E: {
      description: 'Blake2b-512 Digest. Self-addressing derivation.',
      ...objectMap(lengths, v => 2 * v)
    },
    F: {
      description: 'SHA2-512 Digest. Self-addressing derivation.',
      ...objectMap(lengths, v => 2 * v)
    }
  }
}

function encode (buf, to) {
  let derivation = derivationCodes[to.charAt(0)]
  if (!isNaN(Number(to.charAt(0)))) derivation = derivation[to.charAt(1)]
  if (!Buffer.isBuffer(buf)) throw new Error('Must be a buffer')
  if (buf.length !== derivation.dataBytes) throw new Error(`Wrong buffer length: Received ${buf.length} and expected ${derivation.dataBytes}.`)
  const base64 = buf.toString('base64')
  const sliced = base64.substr(0, ((4 * BYTES) + 2) / 3)
  return `${to}${sliced}`
}

function decode (base64) {
  let derivation = derivationCodes[base64.charAt(0)]
  if (!isNaN(Number(base64.charAt(0)))) derivation = derivation[base64.charAt(1)]
  const sliced = base64.substr(derivation.padLength)
  return Buffer.from(sliced, 'base64')
}

console.log('ENCODED', encode(seed, '0A'))
console.log('DECODED', decode(encode(seed, '0A'), '0A'))
