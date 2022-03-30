import { HMACAlgorithm } from "utils";
import { createHmac } from "node:crypto";

const generateHOTP = (secret: Buffer, movingFactor: number, codeLength = 6, truncationOffset=-1, algorithm = HMACAlgorithm.SHA1) => {
    const data = Buffer.from('12345678901234567890', 'ascii')

    // Intermediate values
    const buffer = Buffer.alloc(8)
    for (let i = buffer.length - 1; i >= 0; i--) {
        buffer[i] = movingFactor & 0xff;
        movingFactor >>= 8;
    }
    const hmac = createHmac(algorithm, secret);
    hmac.update(buffer)
    const hash = new Int8Array(hmac.digest());
    let offset = hash[hash.length - 1] & 0xf
    if(0 <= truncationOffset && truncationOffset < (hash.length-4)){
        offset = truncationOffset
    }
    const binary =
            ((+hash[offset] & 0x7f) << 24)
            | ((+hash[offset + 1] & 0xff) << 16)
            | ((+hash[offset + 2] & 0xff) << 8)
            | (+hash[offset + 3] & 0xff);
    return (binary % 10**codeLength).toString().padStart(codeLength, '0');
}

const validateHOTP = (secret: Buffer, movingFactor: number, slidingWindow=0, truncationOffset=-1, algorithm = HMACAlgorithm.SHA1) => {
    
}