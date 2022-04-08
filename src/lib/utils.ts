enum HMACAlgorithm {
  SHA1 = 'sha1',
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

type HOTPValidationResult = {
  success: boolean
  movingFactor: number
}

export { HMACAlgorithm, HOTPValidationResult }
