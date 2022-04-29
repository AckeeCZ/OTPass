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

interface HOTPValidationResult {
  success: boolean
  movingFactor: number
}

const generateSecret = (secretLength: number) => {
  return randomBytes(secretLength)
}

const convertBase32 = (data: Buffer) => {
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

interface URIMakerFunction {
  (
    secret: Buffer,
    serviceName: string,
    user: string,
    type: URItype.HOTP,
    options: {
      algorithm: HMACAlgorithm
      digits: number
      counter?: number
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

const generateURI: URIMakerFunction = (
  secret,
  serviceName,
  user,
  type,
  options,
  params
) => {
  const parameters = Object.entries({
    ...options,
    ...params,
    secret: convertBase32(secret),
  })
    .map(([key, value]) => `${key}=${value}`)
    .join('&')
  return `otpauth://${type}/${serviceName}:${user}?${parameters}`
}

export {
  HMACAlgorithm,
  HOTPValidationResult,
  generateURI,
  URItype,
  generateSecret,
}
