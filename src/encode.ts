import * as crypto from 'crypto'
type BinaryLike = string | NodeJS.ArrayBufferView

import Header from './header'
import Config from './config'
import * as utils from './utils'
import * as _const from './const'

export default class AuthEnc {
  // Cipher
  key: BinaryLike
  seqNum: number
  randVal: Buffer
  finalized: boolean = false
  constructor(cfg: Config) {
    this.key = cfg.key
    this.randVal = cfg.randVal!
    this.seqNum = cfg.sequenceNumber!
  }
  Seal(dst: Buffer, src: Buffer): Buffer {
    return this.seal(dst, src, false)
  }
  SealFinal(dst: Buffer, src: Buffer): Buffer {
    return this.seal(dst, src, true)
  }
  private seal(dst: Buffer, src: Buffer, finalize: boolean): Buffer {
    if (this.finalized) {
      // callers are not supposed to call Seal(Final) after a SealFinal call happened
      throw new Error('sio: cannot seal any package after final one')
    }
    this.finalized = finalize

    let header = new Header(dst.subarray(0, _const.HeaderSize))
    header.SetLength(src.length)
    header.SetRand(this.randVal, finalize)

    let nonce = Buffer.alloc(12)
    nonce.set(header.Nonce())
    nonce.set(utils.PutUint32LE(utils.Uint32LE(nonce.subarray(8, 12)) ^ this.seqNum), 8)
    let cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonce)
    cipher.setAAD(header.AAD())
    let cipherText = Buffer.concat([
      header.h,
      cipher.update(src),
      cipher.final(),
      cipher.getAuthTag()
     ])
    this.seqNum ++
    return cipherText
  }
}
