import { createHmac } from "node:crypto"

const enum HMACAlgorithm {
    SHA1 = 'sha1',
    SHA256 = 'sha256',
    SHA512 = 'sha512'
}


const generateTOTPKey = (algorithm = HMACAlgorithm.SHA1, sharedLength = 160) => {
    if(sharedLength < 128){
        throw new TypeError('Shared secret must be at least 128bits (160b Recommended) - https://datatracker.ietf.org/doc/html/rfc4226#section-4')
    }
    const data = Buffer.from('12345678901234567890', 'ascii')
    const secret = Buffer.from('3132333435363738393031323334353637383930', 'hex')

    for (let index = 0; index < 10; index++) {
        // Intermediate values
        let movingFactor = index;
        const buffer = Buffer.alloc(8)
        for (let i = buffer.length - 1; i >= 0; i--) {
            buffer[i] = movingFactor & 0xff;
            movingFactor >>= 8;
        }
        const hmac = createHmac(algorithm, secret);
        hmac.update(buffer)
        console.log(hmac.digest('hex'));
    }
}

console.log(generateTOTPKey())
