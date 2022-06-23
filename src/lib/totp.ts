import { HOTP } from '../index'
import { HMACAlgorithm, UnixTimestamp } from './utils'

export const generate = (
  secret: Buffer,
  options: {
    codeLength?: number
    truncationOffset?: number
    algorithm?: HMACAlgorithm
    receiveTime?: UnixTimestamp
    timeStep?: number
    clockStart?: UnixTimestamp
  } = {}
) => {
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

export const validate = (
  testedValue: string,
  secret: Buffer,
  slidingWindow = 0,
  options: {
    codeLength?: number
    truncationOffset?: number
    algorithm?: HMACAlgorithm
    receiveTime?: UnixTimestamp
    timeStep?: number
    clockStart?: UnixTimestamp
  } = {}
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
