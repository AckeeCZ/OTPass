import { expect } from 'chai'
import { generateSecret, HMACAlgorithm, TOTP, UnixTimestamp } from '../src'

describe('TOTP', () => {
  describe('RFC6238 reference', () => {
    it('should fit SHA1 reference results', () => {
      const secret20 = Buffer.from('12345678901234567890', 'ascii')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('94287082')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 1111111109,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('07081804')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 1111111111,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('14050471')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 1234567890,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('89005924')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 2000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('69279037')
      expect(
        TOTP.generate(secret20, {
          receiveTime: 20000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        })
      ).to.equal('65353130')
    })
    it('should fit SHA256 reference results', () => {
      const secret32 = Buffer.from('12345678901234567890123456789012', 'ascii')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('46119246')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 1111111109,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('68084774')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 1111111111,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('67062674')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 1234567890,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('91819424')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 2000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('90698825')
      expect(
        TOTP.generate(secret32, {
          receiveTime: 20000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA256,
        })
      ).to.equal('77737706')
    })
    it('should fit SHA512 reference results', () => {
      const secret64 = Buffer.from(
        '1234567890123456789012345678901234567890123456789012345678901234',
        'ascii'
      )
      expect(
        TOTP.generate(secret64, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('90693936')
      expect(
        TOTP.generate(secret64, {
          receiveTime: 1111111109,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('25091201')
      expect(
        TOTP.generate(secret64, {
          receiveTime: 1111111111,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('99943326')
      expect(
        TOTP.generate(secret64, {
          receiveTime: 1234567890,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('93441116')
      expect(
        TOTP.generate(secret64, {
          receiveTime: 2000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('38618901')
      expect(
        TOTP.generate(secret64, {
          receiveTime: 20000000000,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA512,
        })
      ).to.equal('47863826')
    })
  })
  describe('Bulk should equal to singular generation', () => {
    const secret = generateSecret(HMACAlgorithm.SHA1)
    it('every value has to be equal to one generated at the time', () => {
      const bulkValues = TOTP.generateBulk(secret, 50, {
        receiveTime: 0,
        timeStep: 50,
        codeLength: 8,
        algorithm: HMACAlgorithm.SHA1,
      })
      for (let index = 0; index < 50; index++) {
        expect(
          TOTP.generate(secret, {
            receiveTime: 0 + 50 * index,
            timeStep: 50,
            codeLength: 8,
            algorithm: HMACAlgorithm.SHA1,
          })
        ).to.equal(bulkValues[index].code)
      }
    })
  })
})

describe('Validation', () => {
  const generateAndValidate = (
    secret: Buffer,
    slidingWindow: number,
    validationDelay: number,
    options: {
      codeLength?: number
      truncationOffset?: number
      algorithm?: HMACAlgorithm
      receiveTime?: UnixTimestamp
      timeStep?: number
      clockStart?: UnixTimestamp
    }
  ) => {
    return TOTP.validate(
      TOTP.generate(secret, options),
      secret,
      slidingWindow,
      {
        ...options,
        receiveTime:
          (options.receiveTime ?? Math.floor(new Date().getTime() / 1000)) +
          (validationDelay ?? 0),
      }
    )
  }
  describe('RFC6238 reference', () => {
    const secret20 = Buffer.from('12345678901234567890', 'ascii')
    it('should fit SHA1 TOTP reference results', () => {
      expect(
        generateAndValidate(secret20, 0, 0, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
        }).success
      ).to.equal(true)
    })
    it('should fail once time block has elapsed', () => {
      expect(
        generateAndValidate(secret20, 0, 2, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
          timeStep: 30,
        }).success
      ).to.equal(false)
    })
    it('should not fail on time block if sliding window is allowed', () => {
      expect(
        generateAndValidate(secret20, 1, 2, {
          receiveTime: 59,
          codeLength: 8,
          algorithm: HMACAlgorithm.SHA1,
          timeStep: 30,
        }).success
      ).to.equal(false)
    })
  })
})
