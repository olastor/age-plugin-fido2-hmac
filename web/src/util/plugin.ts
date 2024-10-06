import { bech32 } from '@scure/base'
import { base64nopad } from '@scure/base'
import { randomBytes } from '@noble/hashes/utils'
import {
  x25519Wrap,
  x25519Unwrap,
  identityToRecipient as ageIdentityToRecipient,
  Stanza,
} from 'age-encryption'
import { chacha20poly1305 } from '@noble/ciphers/chacha'

import type { Plugin } from 'age-encryption'

export const numberToBytes = (x: number): Uint8Array => {
  const buffer = new ArrayBuffer(2)
  const view = new DataView(buffer)
  view.setUint16(0, x, false)
  const uint8 = new Uint8Array(2)
  uint8.set([view.getUint8(0), view.getUint8(1)], 0)
  return uint8
}

export const bytesToNumber = (bytes: Uint8Array): number => {
  const view = new DataView(bytes.buffer)
  return view.getUint16(0, false)
}

export type Fido2HmacRecipient = {
  version: 1 | 2 | 3 | 4
  salt: Uint8Array
  requirePin: boolean
  credId: Uint8Array
  rpId: string
  x25519PubKey?: Uint8Array
  identityAsRecipient?: boolean
}

export type Fido2HmacIdentity = Fido2HmacRecipient | null

const RECIPIENT_HRP = 'age1fido2-hmac'
const IDENTITY_HRP = 'age-plugin-fido2-hmac-'

export const MAGIC_IDENTITY = 'AGE-PLUGIN-FIDO2-HMAC-1VE5KGMEJ945X6CTRM2TF76'

export const marshalRecipient = (recipient: Fido2HmacRecipient, asIdentity = false): string => {
  let recipientData: Uint8Array

  const rpIdBytes = new TextEncoder().encode(recipient.rpId)
  let recipientSize: number

  switch (recipient.version) {
    case 3:
      recipientSize = 37 + recipient.credId.byteLength + rpIdBytes.byteLength
      recipientData = new Uint8Array(recipientSize)
      recipientData.set(numberToBytes(recipient.version), 0)
      recipientData.set([recipient.requirePin ? 1 : 0], 2)
      recipientData.set(recipient.salt, 3)
      recipientData.set(numberToBytes(recipient.credId.byteLength), 35)
      recipientData.set(recipient.credId, 37)
      recipientData.set(rpIdBytes, 37 + recipient.credId.byteLength)
      break
    case 4:
      if (!recipient.x25519PubKey) throw new Error('missing x25519 pub key')
      recipientSize = 69 + recipient.credId.byteLength + rpIdBytes.byteLength
      recipientData = new Uint8Array(recipientSize)
      recipientData.set(numberToBytes(recipient.version), 0)
      recipientData.set([recipient.requirePin ? 1 : 0], 2)
      recipientData.set(recipient.salt, 3)
      recipientData.set(recipient.x25519PubKey, 35)
      recipientData.set(numberToBytes(recipient.credId.byteLength), 67)
      recipientData.set(recipient.credId, 69)
      recipientData.set(rpIdBytes, 69 + recipient.credId.byteLength)
      break
    default:
      throw new Error(`Version ${recipient.version} not implemented.`)
  }

  return asIdentity
    ? bech32.encode(IDENTITY_HRP, bech32.toWords(recipientData), false).toUpperCase()
    : bech32.encode(RECIPIENT_HRP, bech32.toWords(recipientData), false)
}

const bytesToRecipient = (bytes: Uint8Array): Fido2HmacRecipient => {
  const version = bytesToNumber(bytes.slice(0, 2))

  let credIdLength: number
  switch (version) {
    case 3:
      credIdLength = bytesToNumber(bytes.slice(35, 37))
      return {
        version,
        salt: bytes.slice(3, 35),
        credId: bytes.slice(37, 37 + credIdLength),
        requirePin: bytes[2] === 1,
        rpId:
          bytes.byteLength >= 37 + credIdLength
            ? new TextDecoder().decode(bytes.subarray(37 + credIdLength))
            : '', // TODO: default
      }
    case 4:
      credIdLength = bytesToNumber(bytes.slice(67, 69))
      return {
        version,
        requirePin: bytes[2] === 1,
        salt: bytes.slice(3, 35),
        x25519PubKey: bytes.slice(35, 67),
        credId: bytes.slice(69, 69 + credIdLength),
        rpId:
          bytes.byteLength >= 69 + credIdLength
            ? new TextDecoder().decode(bytes.subarray(69 + credIdLength))
            : '', // TODO: default
      }
    default:
      throw new Error(`Version ${version} not implemented.`)
  }
}

export const parseRecipient = (recipientStr: string): Fido2HmacRecipient => {
  const { bytes } = bech32.decodeToBytes(recipientStr)
  return bytesToRecipient(bytes)
}

const obtainSecretFromToken = async (recipient: Fido2HmacRecipient): Promise<Uint8Array> => {
  const assertion = await navigator.credentials.get({
    publicKey: {
      allowCredentials: [{ id: recipient.credId, type: 'public-key' }],
      timeout: 60000,
      challenge: randomBytes(12),
      extensions: { prf: { eval: { first: recipient.salt } } },
    },
  })

  return new Uint8Array(assertion.getClientExtensionResults().prf.results.first)
}

export const generateNewRecipient = async (symmetric = false, asIdentity = false) => {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: {
        name: '',
        id: 'localhost',
      },
      user: {
        id: randomBytes(12),
        name: base64nopad.encode(randomBytes(6)),
        displayName: base64nopad.encode(randomBytes(6)),
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
      },
      extensions: { prf: {} },

      // unused without attestation so a dummy value is fine.
      challenge: new Uint8Array([0]).buffer,
    },
  })

  const recipient: Fido2HmacRecipient = {
    version: symmetric ? 3 : 4,
    salt: randomBytes(32),
    requirePin: true,
    credId: new Uint8Array(cred.rawId),
    rpId: window.location.hostname,
  }

  if (!symmetric) {
    const secret = await obtainSecretFromToken(recipient)
    const x25519Identity = bech32.encode('AGE-SECRET-KEY-', bech32.toWords(secret)).toUpperCase()
    const x25519Recipient = await ageIdentityToRecipient(x25519Identity)
    recipient.x25519PubKey = bech32.decodeToBytes(x25519Recipient).bytes
  }

  if (!asIdentity) {
    return {
      recipient: marshalRecipient(recipient),
      identity: MAGIC_IDENTITY,
    }
  }

  return {
    recipient: symmetric ? '' : bech32.encode('age', bech32.toWords(recipient.x25519PubKey as Uint8Array)),
    identity: marshalRecipient(recipient, true),
  }
}

export const wrapFileKey = async (
  recipient: Fido2HmacRecipient,
  fileKey: Uint8Array,
): Promise<Stanza> => {
  let secret: Uint8Array
  let wrappedKey: Uint8Array

  const textEncode = (s: string) => base64nopad.encode(new TextEncoder().encode(s))

  switch (recipient.version) {
    case 3:
      secret = await obtainSecretFromToken(recipient)
      const nonce = randomBytes(12)
      const chacha = chacha20poly1305(secret, nonce)
      wrappedKey = chacha.encrypt(fileKey)

      const args = [
        'fido2-hmac',
        textEncode('3'),
        base64nopad.encode(recipient.salt),
        base64nopad.encode(nonce),
      ]

      if (!recipient.identityAsRecipient) {
        args.push(
          textEncode(recipient.requirePin ? '1' : '0'),
          base64nopad.encode(recipient.credId),
          textEncode(recipient.rpId),
        )
      }

      return new Stanza(args, wrappedKey)
    case 4:
      if (!recipient.x25519PubKey) throw new Error('invalid recipient')
      const x25519Stanza = await x25519Wrap(fileKey, recipient.x25519PubKey)
      if (recipient.identityAsRecipient) return x25519Stanza
      return new Stanza(
        [
          'fido2-hmac',
          textEncode('4'),
          x25519Stanza.args[1],
          textEncode(recipient.requirePin ? '1' : '0'),
          base64nopad.encode(recipient.salt),
          base64nopad.encode(recipient.credId),
          textEncode(recipient.rpId),
        ],
        x25519Stanza.body,
      )
    default:
      throw new Error(`Version ${recipient.version} not implemented.`)
  }
}

export const identityToRecipient = (identity: string): string => {
  if (identity === MAGIC_IDENTITY) throw new Error('Cannot convert magic identity to recipient')
  const { prefix, bytes } = bech32.decodeToBytes(identity)

  if (prefix !== 'age-plugin-fido2-hmac') throw new Error('This is not a supported identity')

  const recipient = bytesToRecipient(bytes)

  switch (recipient.version) {
    case 3:
    case 4:
      if (!recipient.x25519PubKey) throw new Error('invalid recipient')
      return bech32.encode('age', bech32.toWords(recipient.x25519PubKey))
    default:
      throw new Error(`Version ${recipient.version} not implemented.`)
  }
}

const textDecode = (s: string) => new TextDecoder().decode(base64nopad.decode(s))

export const unwrapFileKey = async (
  identity: Fido2HmacIdentity,
  stanzas: Stanza[],
): Promise<Uint8Array | null> => {
  for (const stanza of stanzas) {
    let recipientFromStanza: Partial<Fido2HmacRecipient> = {}

    let secret: Uint8Array

    if (stanza.args[0] === 'X25519' && identity && identity.version === 4) {
      secret = await obtainSecretFromToken(identity as Fido2HmacRecipient)

      try {
        // TODO: this is a hell of a workaround
        const x25519Identity = bech32.encode('AGE-SECRET-KEY-', bech32.toWords(secret)).toUpperCase()
        const x25519Recipient = await ageIdentityToRecipient(x25519Identity)
        const recipientPromise = new Promise<Uint8Array>((resolve) => resolve(
          bech32.decodeToBytes(x25519Recipient).bytes
        ))
        const fileKey = await x25519Unwrap(stanza, {
          identity: secret,
          recipient: recipientPromise
        })
        if (fileKey !== null) return fileKey
        continue
      } catch (err) {
        console.error(err)
        continue
      }
    }

    if (stanza.args[0] === 'fido2-hmac') {
      const version = Number.parseInt(
        new TextDecoder().decode(base64nopad.decode(stanza.args[1])),
      ) as 3 | 4
      if (version !== 3 && version !== 4) continue
      recipientFromStanza.version = version

      switch (version) {
        case 3:
          if (stanza.args.length <= 4 && (!identity || identity.version !== 3)) continue
          if (stanza.args.length > 4 && identity) continue

          recipientFromStanza.salt = base64nopad.decode(stanza.args[2])

          if (identity) {
            recipientFromStanza.requirePin = identity.requirePin
            recipientFromStanza.rpId = identity.rpId
            recipientFromStanza.credId = identity.credId
          } else {
            recipientFromStanza.requirePin = textDecode(stanza.args[4]) === '1'
            recipientFromStanza.credId = base64nopad.decode(stanza.args[5])
            recipientFromStanza.rpId = textDecode(stanza.args[6])
          }

          secret = await obtainSecretFromToken(recipientFromStanza as Fido2HmacRecipient)
          const nonce = base64nopad.decode(stanza.args[3])
          const chacha = chacha20poly1305(secret, nonce)
          try {
            return chacha.decrypt(stanza.body)
          } catch (err) {
            console.error(err)
            continue
          }
        case 4:
          if (identity) continue

          recipientFromStanza.requirePin = textDecode(stanza.args[3]) === '1'
          recipientFromStanza.salt = base64nopad.decode(stanza.args[4])
          recipientFromStanza.credId = base64nopad.decode(stanza.args[5])
          recipientFromStanza.rpId = textDecode(stanza.args[6])

          secret = await obtainSecretFromToken(recipientFromStanza as Fido2HmacRecipient)
          const x25519Stanza = new Stanza(['X25519', stanza.args[2]], stanza.body)

          try {
            // TODO: this is a hell of a workaround
            const x25519Identity = bech32.encode('AGE-SECRET-KEY-', bech32.toWords(secret)).toUpperCase()
            const x25519Recipient = await ageIdentityToRecipient(x25519Identity)
            const recipientPromise = new Promise<Uint8Array>((resolve) => resolve(
              bech32.decodeToBytes(x25519Recipient).bytes
            ))
            const fileKey = await x25519Unwrap(x25519Stanza, { identity: secret, recipient: recipientPromise })
            if (fileKey !== null) return fileKey
            continue
          } catch (err) {
            console.error(err)
            continue
          }
        default:
          continue
      }
    }
  }

  return null
}

export const Fido2HmacPlugin: Plugin<Fido2HmacRecipient, Fido2HmacIdentity> = {
  name: 'fido2-hmac',
  handleRecipient: bytesToRecipient,
  handleIdentityAsRecipient: (id: Uint8Array): Fido2HmacRecipient => {
    const r = bytesToRecipient(id)
    r.identityAsRecipient = true
    return r
  },
  handleIdentity: (id: Uint8Array): Fido2HmacIdentity => {
    if (new TextDecoder().decode(id) === 'fido2-hmac') return null
    return bytesToRecipient(id) as Fido2HmacIdentity
  },
  wrapFileKey: wrapFileKey,
  unwrapFileKey: unwrapFileKey,
}
