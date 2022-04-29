import { expect } from 'chai'
import { HMACAlgorithm, TOTP } from '../src'

describe('TOTP Generation', () => {
  describe('TOTP reference', () => {
    it('should fit SHA1 TOTP reference results', () => {
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
    it('should fit SHA256 TOTP reference results', () => {
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
    it('should fit SHA512 TOTP reference results', () => {
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
})
