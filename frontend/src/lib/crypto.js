// JavaScript port of the Loom cipher from vault.py, using the browser's Web Crypto
// API for HMAC-SHA256 and PBKDF2. Same design as the Python version:
//   - Loom: 256-bit Feistel network, 8 rounds, HMAC-SHA256 (cut to 16 bytes) as the round function
//   - Counter mode with a fresh 16-byte nonce for every encryption
//   - Encrypt-then-MAC: an HMAC-SHA256 tag over header + nonce + ciphertext, checked BEFORE decrypting
//   - Master password -> PBKDF2-SHA256 (600,000 iterations) -> split into encryption key and MAC key
//
// Differences from vault.py: it uses PBKDF2 (the fallback vault.py already supports) because browsers
// have no built-in scrypt, and each field is sealed on its own so rows can be stored separately.
// Everything runs in the browser; the master password and plaintext are never sent anywhere.

const enc = new TextEncoder()
const dec = new TextDecoder()

const BLOCK_SIZE = 32
const HALF = 16
const ROUNDS = 8
const NONCE_SIZE = 16
const TAG_SIZE = 32
const PBKDF2_ITERATIONS = 600000

const toB64 = (bytes) => btoa(String.fromCharCode(...bytes))
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

function xor(a, b) {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]
  return out
}

const importHmacKey = (raw, usages = ['sign']) =>
  crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, usages)

const hmac = async (key, data) => new Uint8Array(await crypto.subtle.sign('HMAC', key, data))

// ---------------------------------------------------------------------------
// The Loom cipher
// ---------------------------------------------------------------------------

export async function makeLoom(key) {
  if (key.length !== 32) throw new Error('Loom needs a 32-byte key')

  // Key schedule: an independent-looking key for every round.
  const base = await importHmacKey(key)
  const roundKeys = []
  for (let i = 0; i < ROUNDS; i++) {
    const raw = await hmac(base, concat(enc.encode('loom round key '), Uint8Array.of(i)))
    roundKeys.push(await importHmacKey(raw))
  }

  // Round function: a keyed pseudorandom function of one half-block.
  const f = async (roundKey, half) => (await hmac(roundKey, half)).slice(0, HALF)

  async function encryptBlock(block) {
    let left = block.slice(0, HALF)
    let right = block.slice(HALF)
    for (const rk of roundKeys) {
      ;[left, right] = [right, xor(left, await f(rk, right))]
    }
    return concat(left, right)
  }

  async function decryptBlock(block) {
    let left = block.slice(0, HALF)
    let right = block.slice(HALF)
    for (const rk of [...roundKeys].reverse()) {
      ;[left, right] = [xor(right, await f(rk, left)), left]
    }
    return concat(left, right)
  }

  // Counter mode: XOR data with Loom(nonce||0), Loom(nonce||1), ... (encrypt and decrypt are identical)
  async function ctr(nonce, data) {
    if (nonce.length !== NONCE_SIZE) throw new Error('nonce must be 16 bytes')
    const blocks = Math.ceil(data.length / BLOCK_SIZE)
    const keystream = new Uint8Array(blocks * BLOCK_SIZE)
    for (let counter = 0; counter < blocks; counter++) {
      const counterBlock = concat(nonce, new Uint8Array(NONCE_SIZE))
      new DataView(counterBlock.buffer).setUint32(BLOCK_SIZE - 4, counter) // 16-byte big-endian counter
      keystream.set(await encryptBlock(counterBlock), counter * BLOCK_SIZE)
    }
    return xor(data, keystream.slice(0, data.length))
  }

  return { encryptBlock, decryptBlock, ctr }
}

// ---------------------------------------------------------------------------
// Keys from the master password
// ---------------------------------------------------------------------------

export async function deriveKeys(masterPassword, salt, iterations = PBKDF2_ITERATIONS) {
  // Normalize so an accent typed as one character or as two gives the same key.
  const password = enc.encode(masterPassword.normalize('NFC'))
  const material = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  const stretched = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256)
  )
  // Key separation: one stretched key becomes an encryption key and a MAC key.
  const stretchedKey = await importHmacKey(stretched)
  const encKey = await hmac(stretchedKey, enc.encode('loom encryption key'))
  const macKey = await hmac(stretchedKey, enc.encode('loom mac key'))
  return { loom: await makeLoom(encKey), macKey: await importHmacKey(macKey, ['sign', 'verify']) }
}

// ---------------------------------------------------------------------------
// Authenticated encryption: encrypt with Loom, then MAC
// ---------------------------------------------------------------------------

// Length-prefix the header so bytes can't be shifted between fields.
function macInput(header, nonce, ciphertext) {
  const len = new Uint8Array(8)
  new DataView(len.buffer).setUint32(4, header.length)
  return concat(len, header, nonce, ciphertext)
}

export async function seal(keys, plaintext, header) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE)) // fresh every time, never reused
  const ciphertext = await keys.loom.ctr(nonce, plaintext)
  const tag = await hmac(keys.macKey, macInput(header, nonce, ciphertext))
  return concat(nonce, ciphertext, tag)
}

export async function unseal(keys, sealed, header) {
  if (sealed.length < NONCE_SIZE + TAG_SIZE) throw new Error('Corrupt data')
  const nonce = sealed.slice(0, NONCE_SIZE)
  const tag = sealed.slice(sealed.length - TAG_SIZE)
  const ciphertext = sealed.slice(NONCE_SIZE, sealed.length - TAG_SIZE)
  // crypto.subtle.verify compares in constant time, and runs BEFORE any decryption.
  const ok = await crypto.subtle.verify('HMAC', keys.macKey, tag, macInput(header, nonce, ciphertext))
  if (!ok) throw new Error('Wrong master password, or the data was modified')
  return keys.loom.ctr(nonce, ciphertext)
}

// ---------------------------------------------------------------------------
// App-facing API (used by the vault page)
// ---------------------------------------------------------------------------

export async function deriveKey(masterPassword, userId) {
  const keys = await deriveKeys(masterPassword, enc.encode(`liphr:${userId}`))
  return { ...keys, userId }
}

// The header binds each ciphertext to this user and this field, so entries can't be
// swapped between fields or between accounts without the MAC failing.
const headerFor = (key, field) => enc.encode(`liphr-v1:${key.userId}:${field}`)

export async function encrypt(key, plaintext, field) {
  return toB64(await seal(key, enc.encode(plaintext), headerFor(key, field)))
}

export async function decrypt(key, b64, field) {
  return dec.decode(await unseal(key, fromB64(b64), headerFor(key, field)))
}
