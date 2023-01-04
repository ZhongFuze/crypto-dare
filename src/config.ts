import * as crypto from 'crypto';
import * as _const from './const';
type BinaryLike = string | NodeJS.ArrayBufferView;

class Config {
  key: BinaryLike;
  sequenceNumber?: number = 0;
  randVal?: Buffer;
  payloadSize?: number = 0;
  constructor(key: BinaryLike) {
    this.key = key;
  }
  setConfigDefaults() {
    if (this.randVal == null) {
      this.randVal = crypto.randomBytes(12);
    }
    if (this.payloadSize === 0) {
      this.payloadSize = _const.MaxPayloadSize;
    }
  }
}

export default Config;
