import * as fs from 'fs';
import * as crypto from 'crypto';
import * as scrypt from 'scrypt-js';

import * as _const from './const';
import Config from './config';
import EncReader from './encrypt';
import DecReader from './decrypt';

type BinaryLike = string | NodeJS.ArrayBufferView;

export default class DARE {
  src: string;
  dst: string;
  password: string;
  constructor(pswd: string, src: string, dst: string) {
    this.password = pswd.normalize('NFKC');
    this.src = src;
    this.dst = dst;
  }
  EncryptDeriveKey() {
    const pswd = Buffer.from(this.password);
    const salt = crypto.randomBytes(32);
    const N = 32768;
    const r = 16;
    const p = 1;
    const dkLen = 32;
    const ws = fs.createWriteStream(this.dst);
    ws.write(salt);
    ws.close();
    return new Promise((resolve, reject) => {
      ws.on('finish', () => {
        const key = scrypt.syncScrypt(pswd, salt, N, r, p, dkLen);
        resolve(key);
      });
      ws.on('error', (err) => reject(err));
    });
  }
  DecryptDeriveKey() {
    const pswd = Buffer.from(this.password);
    const N = 32768;
    const r = 16;
    const p = 1;
    const dkLen = 32;
    const data: Buffer[] = [];
    const rs = fs.createReadStream(this.src, { start: 0, end: 31 });
    return new Promise((resolve, reject) => {
      rs.on('data', (chunk) => {
        data.push(Buffer.from(chunk));
      });
      rs.on('end', () => {
        const salt = Buffer.concat(data);
        const key = scrypt.syncScrypt(pswd, salt, N, r, p, dkLen);
        resolve(key);
      });
      rs.on('error', (err) => reject(err));
    });
  }
  async Encrypt() {
    // deriveKey: BinaryLike
    const deriveKey = (await Promise.resolve(this.EncryptDeriveKey())) as Uint8Array;
    const readStream = fs.createReadStream(this.src, { highWaterMark: _const.MaxPayloadSize, start: 0 });
    const writeStream = fs.createWriteStream(this.dst, { flags: 'a' });
    let n = 0;
    const config = new Config(deriveKey);
    config.setConfigDefaults();
    const reader = new EncReader(config);
    return new Promise((resolve, reject) => {
      readStream.on('error', (err) => reject(err));
      readStream.on('data', (chunk) => {
        const cipherText = reader.Read(Buffer.from(chunk));
        writeStream.write(cipherText);
        n++;
      });
      readStream.on('end', () => {
        writeStream.close();
        resolve(n);
      });
    });
  }
  async Decrypt() {
    // deriveKey: BinaryLike
    const deriveKey = (await Promise.resolve(this.DecryptDeriveKey())) as Uint8Array;
    const readStream = fs.createReadStream(this.src, { highWaterMark: _const.MaxPackageSize, start: 32 });
    const writeStream = fs.createWriteStream(this.dst);
    let n = 0;
    const config = new Config(deriveKey);
    config.setConfigDefaults();
    const reader = new DecReader(config);
    return new Promise((resolve, reject) => {
      readStream.on('error', (err) => reject(err));
      readStream.on('data', (chunk) => {
        const plainText = reader.Read(Buffer.from(chunk));
        writeStream.write(plainText);
        n++;
      });
      readStream.on('end', () => {
        writeStream.close();
        resolve(n);
      });
    });
  }
}
