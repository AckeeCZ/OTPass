import { createHmac } from "node:crypto"







const generateTOTPKey = (algorithm = HMACAlgorithm.SHA1, sharedLength = 160) => {
    if(sharedLength < 128){
        throw new TypeError('Shared secret must be at least 128bits (160b Recommended) - https://datatracker.ietf.org/doc/html/rfc4226#section-4')
    }
}

export default generateHOTP;
