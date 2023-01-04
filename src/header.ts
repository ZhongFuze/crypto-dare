import * as _const from './const';
import * as utils from './utils';

export default class Header {
  h: Buffer;
  constructor(h: Buffer) {
    this.h = h;
  }
  Cipher(): Buffer {
    return this.h.subarray(1, 2); // this.h[1]
  }
  SetCipher(cipher: Buffer) {
    this.h.set(cipher, 1);
  }
  Length(): number {
    return utils.Uint16LE(this.h.subarray(2, 4)) + 1;
  }
  SetLength(length: number) {
    this.h.set(utils.PutUint16LE(length - 1), 2);
  }
  IsFinal(): boolean {
    return (this.h[4] & 0x80) === 0x80;
  }
  Nonce(): Buffer {
    return this.h.subarray(4, _const.HeaderSize);
  }
  AAD(): Buffer {
    return this.h.subarray(0, 4);
  }
  SetRand(randVal: Buffer, final: boolean) {
    this.h.set(randVal, 4); // equivalent to copy
    if (final) {
      this.h[4] |= 0x80;
    } else {
      this.h[4] &= 0x7f;
    }
  }
  GetHeader(): Buffer {
    return this.h;
  }
}
