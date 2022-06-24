import { expect } from 'chai'
import { HMACAlgorithm, HOTP } from '../src'

describe('HOTP', () => {
  describe('RFC4226 reference', () => {
    const referenceSecret = Buffer.from(
      '3132333435363738393031323334353637383930',
      'hex'
    )

    it('should fit HOTP reference results', () => {
      expect(HOTP.generate(referenceSecret, 1)).to.equal('287082')
      expect(HOTP.generate(referenceSecret, 0)).to.equal('755224')
      expect(HOTP.generate(referenceSecret, 2)).to.equal('359152')
      expect(HOTP.generate(referenceSecret, 3)).to.equal('969429')
      expect(HOTP.generate(referenceSecret, 4)).to.equal('338314')
      expect(HOTP.generate(referenceSecret, 5)).to.equal('254676')
      expect(HOTP.generate(referenceSecret, 6)).to.equal('287922')
      expect(HOTP.generate(referenceSecret, 7)).to.equal('162583')
      expect(HOTP.generate(referenceSecret, 8)).to.equal('399871')
      expect(HOTP.generate(referenceSecret, 9)).to.equal('520489')
    })
  })

  const referenceSecret = Buffer.from(
    '3132333435363738393031323334353637383930',
    'hex'
  )
  describe('Parameter support', () => {
    it('should not fail on any supported algorithms', () => {
      Object.values(HMACAlgorithm).forEach(algorithm => {
        expect(() =>
          HOTP.generate(referenceSecret, 0, { algorithm })
        ).to.not.throw()
      })
    })
  })
  describe('Validation', () => {
    const generateAndValidate = (
      secret: Buffer,
      slidingWindow: number,
      movingFactor: number,
      counterInequality: number,
      options: {
        codeLength?: number
        truncationOffset?: number
        algorithm?: HMACAlgorithm
      }
    ) => {
      return HOTP.validate(
        HOTP.generate(secret, movingFactor, options),
        secret,
        movingFactor - counterInequality,
        slidingWindow,
        options
      )
    }
    it('should validate basic results', () => {
      Object.values(HMACAlgorithm).forEach(algorithm => {
        expect(
          generateAndValidate(referenceSecret, 0, 0, 0, { algorithm }).success
        ).to.equal(true)
      })
    })
    it('should be able to support sliding window', () => {
      Object.values(HMACAlgorithm).forEach(algorithm => {
        expect(
          generateAndValidate(referenceSecret, 1, 0, 1, { algorithm }).success
        ).to.equal(true)
      })
    })
    it('should not allow backwards sliding window (repeat attack)', () => {
      Object.values(HMACAlgorithm).forEach(algorithm => {
        expect(
          generateAndValidate(referenceSecret, 1, 0, -1, { algorithm }).success
        ).to.equal(false)
      })
    })
  })
})
