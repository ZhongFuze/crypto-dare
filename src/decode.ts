import * as crypto from 'crypto'
type BinaryLike = string | NodeJS.ArrayBufferView

import Header from './header'
import Package from './package'
import Config from './config'
import * as utils from './utils'
import * as _const from './const'

export default class AuthDec {
  key: BinaryLike
  seqNum: number
  refHeader?: Header
	finalized: boolean = false
  constructor(cfg: Config) {
    this.key = cfg.key
    this.seqNum = cfg.sequenceNumber!
  }
  Open(src: Buffer): Buffer {
    if (this.finalized) {
      throw new Error('unexpected data after final package')
    }
    if (src.length < (_const.HeaderSize + _const.TagSize)) {
      throw new Error('invalid payload size')
    }

    const pkg = new Package(src)
    const header = pkg.Header()
    if (this.refHeader == null) {
      this.refHeader = new Header(header.GetHeader())
    }

    if (_const.HeaderSize + header.Length() + _const.TagSize !== src.length) {
      throw new Error('invalid payload size')
    }
    if (!header.IsFinal() && header.Length() !== _const.MaxPayloadSize) {
      throw new Error('invalid payload size')
    }

    const refNonce = this.refHeader.Nonce()
    if (header.IsFinal()) {
      this.finalized = true
      refNonce[0] |= 0x80
    }

    if (!crypto.timingSafeEqual(header.Nonce(), refNonce)) {
      throw new Error('header nonce mismatch')
    }

    const nonce = Buffer.alloc(12)
    nonce.set(header.Nonce())
    nonce.set(utils.PutUint32LE(utils.Uint32LE(nonce.subarray(8, 12)) ^ this.seqNum), 8)

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce)
    decipher.setAAD(header.AAD())
    decipher.setAuthTag(pkg.GetAuthTag())

    const cipherText = src.subarray(_const.HeaderSize, _const.HeaderSize+header.Length())
    const plainText = Buffer.concat([
      decipher.update(cipherText),
      decipher.final(),
     ])
    this.seqNum ++
    return plainText
  }
}
