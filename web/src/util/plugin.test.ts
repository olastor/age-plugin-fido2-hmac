import { expect, describe } from 'vitest'
import { test, fc } from '@fast-check/vitest'
import {
  numberToBytes,
  bytesToNumber,
  marshalRecipient,
  parseRecipient,
  unwrapFileKey,
  wrapFileKey,
} from './plugin'
import { isEqual } from 'lodash'
import { bech32 } from '@scure/base'

fc.configureGlobal({
  numRuns: 100,
})

describe('Plugin Fido2 Hmac', () => {
  describe('Properties', () => {
    test.prop({
      uint16: fc.integer({ min: 0, max: 65535 }),
    })(
      'check bytes to number',
      async ({ uint16 }) => {
        return bytesToNumber(numberToBytes(uint16)) === uint16
      },
    )

    test.prop({
      recipient: fc.record({
        version: fc.constant(3),
        requirePin: fc.constant(true),
        salt: fc.uint8Array({ minLength: 32, maxLength: 32 }),
        credId: fc.uint8Array({ minLength: 24, maxLength: 100 }),
        rpId: fc.domain(),
      }),
    })(
      'check recipient parsing v3',
      async ({ recipient }) => {
        return isEqual(recipient, parseRecipient(marshalRecipient(recipient)))
      },
    )

    test.prop({
      recipient: fc.record({
        version: fc.constant(4),
        requirePin: fc.constant(true),
        salt: fc.uint8Array({ minLength: 32, maxLength: 32 }),
        x25519PubKey: fc.uint8Array({ minLength: 32, maxLength: 32 }),
        credId: fc.uint8Array({ minLength: 24, maxLength: 100 }),
        rpId: fc.domain(),
      }),
    })(
      'check recipient parsing v4',
      async ({ recipient }) => {
        return isEqual(recipient, parseRecipient(marshalRecipient(recipient)))
      },
    )

    // test.prop({
    //   recipient: fc.record({
    //     version: fc.constant(3),
    //     requirePin: fc.constant(true),
    //     salt: fc.uint8Array({ minLength: 32, maxLength: 32 }),
    //     credId: fc.uint8Array({ minLength: 24, maxLength: 100 }),
    //     rpId: fc.domain(),
    //   }),
    //   fileKey: fc.uint8Array({ minLength: 12, maxLength: 12 }),
    // })(
    //   'decryption should invert encryption with identity/recipient (string plaintext)',
    //   async ({ recipient, fileKey }) => {
    //     const { bytes: recipientData } = bech32.decodeToBytes(marshalRecipient(recipient))
    //     console.log(wrapFileKey(fileKey, recipientData))
    //     return isEqual(fileKey, unwrapFileKey(wrapFileKey(fileKey, recipientData), recipientData))
    //   },
    // )
  })
})
