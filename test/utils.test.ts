import { expect } from 'chai'
import { HMACAlgorithm, URItype, generateURI } from '../src'

describe('URI Generation', () => {
  it('should generate URI', () => {
    const buf = Buffer.from([
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef,
    ])

    const uri = new URL(
      generateURI(
        buf,
        'serviceName',
        'user',
        URItype.HOTP,
        { algorithm: HMACAlgorithm.SHA256, digits: 6 },
        { issuer: 'Example' }
      )
    )
    expect(uri.protocol).to.equal('otpauth:')
    expect(uri.host).to.equal(URItype.HOTP)
    expect(uri.pathname).to.equal('/serviceName:user')
    expect(uri.searchParams.get('algorithm')).to.equal(HMACAlgorithm.SHA256)
    expect(uri.searchParams.get('digits')).to.equal('6')
    expect(uri.searchParams.get('issuer')).to.equal('Example')
  })
})