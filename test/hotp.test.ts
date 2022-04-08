import { expect } from 'chai'
import { HMACAlgorithm, HOTP } from '../src'

describe('HOTP Generation', () => {
  describe('HOTP reference', () => {
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

  describe('Parameter support', () => {
    it('should not fail on any supported algorithms', () => {
      const referenceSecret = Buffer.from(
        '3132333435363738393031323334353637383930',
        'hex'
      )

      Object.values(HMACAlgorithm).forEach(algorithm => {
        expect(() =>
          HOTP.generate(referenceSecret, 0, { algorithm })
        ).to.not.throw()
      })
    })
  })
})
