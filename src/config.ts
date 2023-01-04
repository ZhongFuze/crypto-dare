import * as crypto from 'crypto'
import * as _const from './const'
type BinaryLike = string | NodeJS.ArrayBufferView;

class Config {
  key: BinaryLike
  sequenceNumber?: number = 0
  randVal?: Buffer
  payloadSize?: number = 0
  constructor(key: BinaryLike) {
    this.key = key

  }
  setConfigDefaults() {
    if (this.randVal == null) {
      // this.randVal = crypto.randomBytes(12)
      this.randVal = Buffer.from([0xae, 0xcd, 0x47, 0x2f, 0x5, 0xb, 0xa7, 0xbe, 0x36, 0xc0, 0x7b, 0xaa])
    }
    if (this.payloadSize === 0) {
      this.payloadSize = _const.MaxPayloadSize
    }
  }
}

export default Config
