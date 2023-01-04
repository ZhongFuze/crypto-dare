import * as crypto from 'crypto'
import * as _const from './const'
import * as utils from './utils'
import Config from './config'
type BinaryLike = string | NodeJS.ArrayBufferView;

export class Header {
  h: Buffer
  constructor(h: Buffer) {
    this.h = h
  }
  Cipher(): Buffer {
    return this.h.subarray(1, 2); // this.h[1]
  }
  SetCipher(cipher: Buffer) {
    this.h.set(cipher, 1)
  }
  Length(): number {
    return utils.Uint16LE(this.h.subarray(2, 4)) + 1
  }
  SetLength(length: number) {
    this.h.set(utils.PutUint16LE(length - 1), 2)
  }
  IsFinal(): boolean {
    return ((this.h[4] & 0x80) == 0x80)
  }
  Nonce(): Buffer {
    return this.h.subarray(4, _const.HeaderSize)
  }
  AAD(): Buffer {
    return this.h.subarray(0, 4)
  }
  SetRand(randVal: Buffer, final: boolean) {
    this.h.set(randVal, 4) // equivalent to copy
    if (final) {
      this.h[4] |= 0x80
    } else {
      this.h[4] &= 0x7F
    }
  }
  GetHeader(): Buffer {
    return this.h
  }
}

export class Package {
  p: Buffer
  header: Header
  constructor(p: Buffer) {
    this.p = p
    this.header = new Header(p.subarray(0, _const.HeaderSize))
  }
  Payload(): Buffer {
    return this.p.subarray(_const.HeaderSize, _const.HeaderSize+this.header.Length())
  }
  CipherText(): Buffer {
    return this.p.subarray(_const.HeaderSize, this.p.byteLength)
  }
  Length(): number {
    return _const.HeaderSize + _const.TagSize + this.header.Length()
  }
  GetHeader(): Buffer {
    return this.header.GetHeader()
  }
  SetHeader(h: Buffer) {
    this.header = new Header(h)
  }
  Header(): Header {
    return this.header
  }
  GetAuthTag(): Buffer {
    return this.p.subarray(_const.HeaderSize+this.header.Length(), _const.HeaderSize+this.header.Length()+_const.TagSize)
  }
}

export class AuthEnc {
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
    // let tag = cipher.getAuthTag()
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

export class AuthDec {
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

    let pkg = new Package(src)
    let header = pkg.Header()
    if (this.refHeader == null) {
      this.refHeader = new Header(header.GetHeader())
    }

    if (_const.HeaderSize + header.Length() + _const.TagSize != src.length) {
      throw new Error('invalid payload size')
    }
    if (!header.IsFinal() && header.Length() != _const.MaxPayloadSize) {
      throw new Error('invalid payload size')
    }

    let refNonce = this.refHeader.Nonce()
    if (header.IsFinal()) {
      this.finalized = true
      refNonce[0] |= 0x80
    }

    if (!crypto.timingSafeEqual(header.Nonce(), refNonce)) {
      throw new Error('header nonce mismatch')
    }

    let nonce = Buffer.alloc(12)
    nonce.set(header.Nonce())
    nonce.set(utils.PutUint32LE(utils.Uint32LE(nonce.subarray(8, 12)) ^ this.seqNum), 8)

    let decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonce)
    decipher.setAAD(header.AAD())
    decipher.setAuthTag(pkg.GetAuthTag())

    let cipherText = src.subarray(_const.HeaderSize, _const.HeaderSize+header.Length())
    let plainText = Buffer.concat([
      decipher.update(cipherText),
      decipher.final(),
     ])
    this.seqNum ++
    return plainText
  }
}
