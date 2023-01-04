import Header from './header';
import * as _const from './const';

export default class Package {
  p: Buffer;
  header: Header;
  constructor(p: Buffer) {
    this.p = p;
    this.header = new Header(p.subarray(0, _const.HeaderSize));
  }
  Payload(): Buffer {
    return this.p.subarray(_const.HeaderSize, _const.HeaderSize + this.header.Length());
  }
  CipherText(): Buffer {
    return this.p.subarray(_const.HeaderSize, this.p.byteLength);
  }
  Length(): number {
    return _const.HeaderSize + _const.TagSize + this.header.Length();
  }
  GetHeader(): Buffer {
    return this.header.GetHeader();
  }
  SetHeader(h: Buffer) {
    this.header = new Header(h);
  }
  Header(): Header {
    return this.header;
  }
  GetAuthTag(): Buffer {
    return this.p.subarray(
      _const.HeaderSize + this.header.Length(),
      _const.HeaderSize + this.header.Length() + _const.TagSize,
    );
  }
}
