import { expect } from 'chai';
import generateHOTP from '../src';


describe('HOTP reference', () => {
    const referenceSecret = Buffer.from('3132333435363738393031323334353637383930', 'hex')
    it('should fit HOTP reference results', () => {
        expect(generateHOTP(referenceSecret, 0)).to.equal('755224')
        expect(generateHOTP(referenceSecret, 1)).to.equal('287082')
        expect(generateHOTP(referenceSecret, 2)).to.equal('359152')
        expect(generateHOTP(referenceSecret, 3)).to.equal('969429')
        expect(generateHOTP(referenceSecret, 4)).to.equal('338314')
        expect(generateHOTP(referenceSecret, 5)).to.equal('254676')
        expect(generateHOTP(referenceSecret, 6)).to.equal('287922')
        expect(generateHOTP(referenceSecret, 7)).to.equal('162583')
        expect(generateHOTP(referenceSecret, 8)).to.equal('399871')
        expect(generateHOTP(referenceSecret, 9)).to.equal('520489')
    })
});
