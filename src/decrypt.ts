import { AuthDec, Package } from "./dare"
import * as _const from './const'
import Config from './config'

export default class DecReader {
  authDec: AuthDec
  buffer: Package
  constructor(cfg: Config) {
    this.authDec = new AuthDec(cfg)
    this.buffer = new Package(Buffer.alloc(_const.MaxPackageSize))
  }
  Read(c: Buffer): Buffer {
    if (c.length == 0 && !this.authDec.finalized) {
      throw new Error('unexpected EOF')
    }
    if (c.length > 0) {
      let nn = c.copy(this.buffer.p)
      this.buffer.SetHeader(c.subarray(0, _const.HeaderSize))
      let p = this.authDec.Open(this.buffer.p.subarray(0, nn))
      p.copy(this.buffer.p, _const.HeaderSize)
      let payload = this.buffer.Payload()
      if (p.length < payload.length) {
        return payload.subarray(0, p.length)
      } else {
        return payload
      }
    }
    return Buffer.from('')
  }
}
