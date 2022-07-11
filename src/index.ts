import * as HOTP from './lib/hotp'
import * as TOTP from './lib/totp'
import {
  HMACAlgorithm,
  generateURI,
  URItype,
  UnixTimestamp,
  generateSecret,
} from './lib/utils'

export {
  TOTP,
  HOTP,
  HMACAlgorithm,
  generateURI,
  generateSecret,
  URItype,
  UnixTimestamp,
}
