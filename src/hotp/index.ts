import { HMACAlgorithm, HOTPValidationResult } from '../utils'
import { createHmac } from 'node:crypto'

export interface HOTPOptions {
  /** Length of generated value */
  codeLength?: number
  truncationOffset?: number
  algorithm?: HMACAlgorithm
}

/**
 * Generate HOTP value
 * @param secret Shared secret, in Buffer form
 * @param movingFactor counter value - how many times was the key requested
 * @param options
 * @returns
 */
export const generate = (
  secret: Buffer,
  movingFactor: number,
  options: HOTPOptions = {}
) => {
  // Default recommended configuration
  const {
    codeLength = 6,
    truncationOffset = -1,
    algorithm = HMACAlgorithm.SHA1,
  } = options

  // Intermediate values
  const buffer = Buffer.alloc(8)
  for (let i = buffer.length - 1; i >= 0; i--) {
    buffer[i] = movingFactor & 0xff
    movingFactor >>= 8
  }
  const hmac = createHmac(algorithm, secret)
  hmac.update(buffer)
  const hash = new Int8Array(hmac.digest())
  let offset = hash[hash.length - 1] & 0xf
  if (truncationOffset >= 0 && truncationOffset < hash.length - 4) {
    offset = truncationOffset
  }
  const binary =
    ((+hash[offset] & 0x7f) << 24) |
    ((+hash[offset + 1] & 0xff) << 16) |
    ((+hash[offset + 2] & 0xff) << 8) |
    (+hash[offset + 3] & 0xff)
  return (binary % 10 ** codeLength).toString().padStart(codeLength, '0')
}

/**
 * Validate testedValue against generated HOTP value, while taking in account sliding window
 * @param testedValue tested HOTP value in string form
 * @param secret Shared secret, in Buffer form
 * @param movingFactor counter value - how many times was the key requested
 * @param slidingWindow how many counter values forward can the validation still succeed
 * @param options
 * @returns
 */
export const validate = (
  testedValue: string,
  secret: Buffer,
  movingFactor: number,
  slidingWindow = 0,
  options: HOTPOptions = {}
): HOTPValidationResult => {
  for (
    let index = movingFactor;
    index <= movingFactor + slidingWindow;
    index++
  ) {
    if (generate(secret, index, options) === testedValue) {
      return { success: true, movingFactor: index }
    }
  }
  return { success: false, movingFactor: -1 }
}
