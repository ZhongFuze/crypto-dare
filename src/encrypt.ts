import AuthEnc from './encode'
import Config from './config'
import * as _const from './const'

export default class EncReader {
  authEnc: AuthEnc
  buffer: Buffer
  firstRead: boolean = true
  constructor(cfg: Config) {
    this.authEnc = new AuthEnc(cfg)
    this.buffer = Buffer.alloc(_const.MaxPackageSize)
  }
  Read(p: Buffer): Buffer {
    if (this.firstRead) {
      this.firstRead = false
      this.buffer.set(p.subarray(0, 1), _const.HeaderSize)
      if (p.length == 0) {
        this.authEnc.finalized = true
        // clear buffer io.EOF
        return Buffer.from('')
      }
    }

    if (this.authEnc.finalized) {
      return Buffer.from('')  // io.EOF
    }

    if (p.length > 0) {
      let n = p.copy(this.buffer, _const.HeaderSize, 0, _const.MaxPayloadSize)
      if (n < _const.MaxPayloadSize) {
        // io.EOF
        let c = this.authEnc.SealFinal(
          this.buffer.subarray(0, _const.HeaderSize),
          this.buffer.subarray(_const.HeaderSize, _const.HeaderSize+1+n)
        )
        return c
      } else {
        let c = this.authEnc.Seal(
          this.buffer.subarray(0, _const.HeaderSize),
          this.buffer.subarray(_const.HeaderSize, _const.HeaderSize+_const.MaxPayloadSize)
        )
        return c
      }
    }
    return Buffer.from('')
  }
}
