import { HOTP } from '../index'
import { HOTPOptions } from '../hotp'
import { UnixTimestamp } from '../utils'

/**
 * Options for TOTP usage
 */
interface TOTPOptions extends HOTPOptions {
  /** Time of authentification, to assume code was (or is supposed to be) valid at this time (should not be manipulated for security reasons) */
  receiveTime?: UnixTimestamp
  /** Period of TOTP value life */
  timeStep?: number
  /** If specific start time was selected instead of standard UNIX time 0 */
  clockStart?: UnixTimestamp
}

/**
 * Generate TOTP value for given parameters
 * @param secret Shared secret, in Buffer form
 * @param options
 * @returns
 */
export const generate = (secret: Buffer, options: TOTPOptions = {}) => {
  const {
    receiveTime = Math.floor(new Date().getTime() / 1000),
    timeStep = 30,
    clockStart = 0,
  } = options
  return HOTP.generate(
    secret,
    Math.floor((receiveTime - clockStart) / timeStep),
    options
  )
}

interface BulkCode {
  code: string
  validityStart: UnixTimestamp
  validityEnd: UnixTimestamp
}

/**
 * Generate bulk TOTP values for given parameters (to reduce amount of requests)
 * @param secret Shared secret, in Buffer form
 * @param amount How many codes forward do you want to generate
 * @param options
 * @returns
 */
export const generateBulk = (
  secret: Buffer,
  amount: number,
  options: TOTPOptions
): BulkCode[] => {
  const {
    receiveTime = Math.floor(new Date().getTime() / 1000),
    timeStep = 30,
    clockStart = 0,
  } = options
  const result: BulkCode[] = []
  for (let index = 0; index <= amount; index++) {
    const timeSlot = Math.floor((receiveTime - clockStart) / timeStep) + index
    result.push({
      code: HOTP.generate(secret, timeSlot, options),
      validityStart: timeSlot * timeStep + clockStart,
      validityEnd: (timeSlot + 1) * timeStep + clockStart,
    })
  }
  return result
}

/**
 * Validate TOTP value vs newly generated value from secret
 * @param testedValue - tested TOTP value
 * @param secret - Shared secret, in Buffer form
 * @param slidingWindow - How far forward in time should the function look (for unsynchronized clocks or delays in program or connection)
 * @param options TOTP options to generate the reference values
 * @returns
 */
export const validate = (
  testedValue: string,
  secret: Buffer,
  slidingWindow = 0,
  options: TOTPOptions = {}
) => {
  const {
    receiveTime = Math.floor(new Date().getTime() / 1000),
    timeStep = 30,
  } = options
  for (let index = 0; index <= slidingWindow; index++) {
    if (
      generate(secret, {
        ...options,
        receiveTime: receiveTime + index * timeStep,
      }) === testedValue
    ) {
      return { success: true }
    }
  }
  return { success: false }
}
