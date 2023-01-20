import { randomBytes } from 'node:crypto'

enum HMACAlgorithm {
  SHA1 = 'sha1',
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

enum URItype {
  HOTP = 'hotp',
  TOTP = 'totp',
}

export type UnixTimestamp = number

/**
 * Returning value of HOTP validation
 */
interface HOTPValidationResult {
  /** Has the validation succeeded withing parameters */
  success: boolean
  /** Counter value where congruence was found, server side counter should be set to this value + 1 to disallow repetition */
  movingFactor: number
}

/**
 * Alias for node:crypto.randomBytes
 * @param secretLength Byte length of the secret, minimum should be 16 bytes, recommended value is 20 bytes or more, also accepts defined algorithms for which it creates optimal length as recommended
 * @returns Secret in buffer form
 */

const generateSecret = (secretLength: number | HMACAlgorithm) => {
  const algorithmToByteSize = {
    [HMACAlgorithm.SHA1]: 20,
    [HMACAlgorithm.SHA256]: 32,
    [HMACAlgorithm.SHA512]: 64,
  }
  if (typeof secretLength === 'string') {
    return randomBytes(algorithmToByteSize[secretLength])
  }
  return randomBytes(secretLength)
}

/**
 * Convert Buffer to base32 according to RFC 4648 (see https://www.rfc-editor.org/rfc/rfc4648) as node doesn't support the encoding
 * @param data Buffer to convert to base32
 * @returns string which is the base32 encoding of the buffer
 */
const convertToBase32 = (data: Buffer) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  let output = ''

  for (let i = 0; i < data.byteLength; i++) {
    value = (value << 8) | data.readUint8(i)
    bits += 8

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31]
  }
  return output
}

const base32ToBuffer = (input: string) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  let index = 0
  const output = Buffer.alloc(Math.ceil((input.length * 5) / 8))
  for (let i = 0; i < input.length; i++) {
    value = (value << 5) | alphabet.indexOf(input[i].toUpperCase())
    bits += 5

    if (bits >= 8) {
      output.writeUInt8((value >>> (bits - 8)) & 255, index++)
      bits -= 8
    }
  }
  return output
}

interface URIMakerFunction {
  (
    secret: Buffer,
    serviceName: string,
    user: string,
    type: URItype.HOTP,
    options: {
      algorithm: HMACAlgorithm
      digits: number
      counter: number
    },
    params: Record<string, string>
  ): string
  (
    secret: Buffer,
    serviceName: string,
    user: string,
    type: URItype.TOTP,
    options: {
      algorithm: HMACAlgorithm
      digits: number
      period?: number
    },
    params: Record<string, string>
  ): string
}

/**
 *
 * @param secret - The shared secret (Arbitrary key as specified in RFC 3548, padding should be omitted)
 * @param serviceName - Service name to be included as identifier for the authentification app
 * @param user - Username to identify the secret by
 * @param type - hotp or totp (hmac one time password / time-based one time password)
 * @param options - The used settings for generating password - algorithm, digits and counter (initial counter value) or period, which one depends on whether hotp or totp is used (counter is required, period is optional - period can be also ignored by many implementations)
 * @param params - Other options to be included in the URI - specifically issuer is highly recommended: https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer, handling of these parameters is highly dependent on implementations
 * @returns The generated URI (ideally to be encoded within QR code for scan)
 */

const generateURI: URIMakerFunction = (
  secret,
  serviceName,
  user,
  type,
  options,
  params
) => {
  const result = new URL(`otpauth://${type}/${serviceName}:${user}`)
  Object.entries({
    ...options,
    ...params,
    secret: convertToBase32(secret),
  }).forEach(([key, value]) =>
    result.searchParams.append(key, value.toString())
  )
  return result.href
}

export {
  HMACAlgorithm,
  HOTPValidationResult,
  generateURI,
  URItype,
  generateSecret,
  convertToBase32,
  base32ToBuffer,
}
