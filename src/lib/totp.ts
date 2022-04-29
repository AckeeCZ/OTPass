import { HOTP } from '../index'
import { HMACAlgorithm } from './utils'

export const generate = (
  secret: Buffer,
  options: {
    codeLength?: number
    truncationOffset?: number
    algorithm?: HMACAlgorithm
    receiveTime?: number
    timeStep?: number
    clockStart?: number
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
