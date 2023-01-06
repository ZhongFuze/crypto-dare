import * as fs from 'fs';
import { PathLike } from 'fs';
import * as crypto from 'crypto';
import * as scrypt from 'scrypt-js';

import { isAbsolute } from './pathutils';
import * as _const from './const';
import Config from './config';
import EncReader from './encrypt';
import DecReader from './decrypt';

export default class DARE {
  private password: Buffer;
  constructor(password: Buffer | string) {
    if (typeof password === 'string') {
      this.password = Buffer.from(password.normalize('NFKC'));
    } else {
      this.password = password;
    }
  }
  EncryptDeriveKey(dst: fs.PathLike): Promise<Uint8Array>;
  EncryptDeriveKey(dst?: undefined): Promise<[Uint8Array, Buffer]>;
  EncryptDeriveKey(dst?: Buffer | fs.PathLike | undefined):
    Promise<Uint8Array | [Uint8Array, Buffer]> | void {
    const salt = crypto.randomBytes(32);
    const N = 32768;
    const r = 16;
    const p = 1;
    const dkLen = 32;
    if (dst != null && isAbsolute(dst!.toString())) {
      // dst: os.path
      const ws = fs.createWriteStream(dst!);
      ws.write(salt);
      ws.close();
      return new Promise((resolve, reject) => {
        ws.on('finish', () => {
          const key = scrypt.syncScrypt(this.password, salt, N, r, p, dkLen);
          resolve(key);
        });
        ws.on('error', (err) => reject(err));
      });
    } else {
      // dst: undefined
      return new Promise((resolve, reject) => {
        try {
          const key = scrypt.syncScrypt(this.password, salt, N, r, p, dkLen);
          resolve([key, salt]);
        } catch (err: any) {
          reject(err);
        }
      });
    }
  }
  DecryptDeriveKey(src: fs.PathLike): Promise<Uint8Array>;
  DecryptDeriveKey(src: Buffer): Promise<Uint8Array>;
  DecryptDeriveKey(src: Buffer | fs.PathLike): Promise<Uint8Array> | void {
    const N = 32768;
    const r = 16;
    const p = 1;
    const dkLen = 32;
    const data: Buffer[] = [];

    if (isAbsolute(src.toString())) {
      // src: os.path
      const rs = fs.createReadStream(src, { start: 0, end: 31 });
      return new Promise((resolve, reject) => {
        rs.on('data', (chunk) => {
          data.push(Buffer.from(chunk));
        });
        rs.on('end', () => {
          const salt = Buffer.concat(data);
          const key = scrypt.syncScrypt(this.password, salt, N, r, p, dkLen);
          resolve(key);
        });
        rs.on('error', (err) => reject(err));
      });
    } else {
      return new Promise((resolve, reject) => {
        try {
          if (Buffer.isBuffer(src)) {
            if (src.byteLength < 32) {
              throw Error('failed to read salt from src');
            }
            const salt = src.subarray(0, 32)
            const key = scrypt.syncScrypt(this.password, salt, N, r, p, dkLen);
            resolve(key);
          } else {
            throw Error('src must be a "Buffer" object');
          }
        } catch (err: any) {
          reject(err)
        }
      });
    }
  }
  Encrypt(src: fs.PathLike, dst: fs.PathLike): void;
  Encrypt(src: fs.PathLike, dst?: undefined): Promise<Buffer>;
  Encrypt(src: Buffer, dst: fs.PathLike): void;
  Encrypt(src: Buffer, dst?: undefined): Promise<Buffer>;
  async Encrypt(src: Buffer | fs.PathLike,  dst?: Buffer | fs.PathLike | undefined):
    Promise<Buffer | number | void> {
    if (dst != null && isAbsolute(dst!.toString())) {
      const deriveKey = (await Promise.resolve(this.EncryptDeriveKey(dst)));
      const writeStream = fs.createWriteStream(dst, { flags: 'a' });
      if (isAbsolute(src.toString())) {
        // read stream -> write stream
        const readStream = fs.createReadStream(src, { highWaterMark: _const.MaxPayloadSize, start: 0 });
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
      } else {
        // Buffer block -> write stream
        let n = 0;
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new EncReader(config);
        return new Promise((resolve, reject) => {
          try {
            if (Buffer.isBuffer(src)) {
              const count = Math.ceil(src.byteLength / _const.MaxPayloadSize);
              for (let i = 0; i < count; i++) {
                let s = i * _const.MaxPayloadSize;
                let e = Math.min(src.byteLength, (i+1) * _const.MaxPayloadSize);
                const chunk = src.subarray(s, e);
                const cipherText = reader.Read(Buffer.from(chunk));
                writeStream.write(cipherText);
                n++;
              }
              if (n === count) {
                writeStream.close();
                resolve(n);
              }
            } else {
              throw Error('src must be a "Buffer" object');
            }
          } catch (err: any) {
            reject(err);
          }
        });
      }
    } else {
      // dst is null
      const [deriveKey, salt] = (await Promise.resolve(this.EncryptDeriveKey()));
      const chunks: Buffer[] = [];
      chunks.push(salt)
      if (isAbsolute(src.toString())) {
        // read stream -> Buffer
        const readStream = fs.createReadStream(src, { highWaterMark: _const.MaxPayloadSize, start: 0 });
        let n = 0;
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new EncReader(config);
        return new Promise((resolve, reject) => {
          readStream.on('error', (err) => reject(err));
          readStream.on('data', (chunk) => {
            const cipherText = reader.Read(Buffer.from(chunk));
            chunks.push(cipherText);
            n++;
          });
          readStream.on('end', () => {
            resolve(Buffer.concat(chunks));
          });
        });
      } else {
        // Buffer -> Buffer
        let n = 0;
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new EncReader(config);
        return new Promise((resolve, reject) => {
          try {
            if (Buffer.isBuffer(src)) {
              const count = Math.ceil(src.byteLength / _const.MaxPayloadSize);
              for (let i = 0; i < count; i++) {
                let s = i * _const.MaxPayloadSize;
                let e = Math.min(src.byteLength, (i+1) * _const.MaxPayloadSize);
                const chunk = src.subarray(s, e);
                const cipherText = reader.Read(Buffer.from(chunk));
                chunks.push(cipherText);
                n++;
              }
              if (n === count) {
                resolve(Buffer.concat(chunks));
              }
            } else {
              throw Error('src must be a "Buffer" object');
            }
          } catch (err: any) {
            reject(err);
          }
        });
      }
    }
  }
  Decrypt(src: fs.PathLike, dst: fs.PathLike): void;
  Decrypt(src: fs.PathLike, dst?: undefined): Promise<Buffer>;
  Decrypt(src: Buffer, dst: fs.PathLike): void;
  Decrypt(src: Buffer, dst?: undefined): Promise<Buffer>;
  async Decrypt(src: Buffer | fs.PathLike,  dst?: Buffer | fs.PathLike | undefined):
  Promise<Buffer | number | void> {
    if (dst != null && isAbsolute(dst!.toString())) {
      const deriveKey = (await Promise.resolve(this.DecryptDeriveKey(src))); // as Uint8Array;
      const writeStream = fs.createWriteStream(dst);
      if (isAbsolute(src.toString())) {
        // read stream -> write stream
        const readStream = fs.createReadStream(src, { highWaterMark: _const.MaxPackageSize, start: 32 });
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
      } else {
        // Buffer block -> write stream
        let n = 0;
        const salt_offset = 32
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new DecReader(config);
        return new Promise((resolve, reject) => {
          try {
            if (Buffer.isBuffer(src)) {
              const count = Math.ceil((src.byteLength - salt_offset) / _const.MaxPackageSize);
              for (let i = 0; i < count; i++) {
                let s = i * _const.MaxPackageSize + salt_offset;
                let e = Math.min(src.byteLength, (i+1) * _const.MaxPackageSize + salt_offset);
                const chunk = src.subarray(s, e);
                const plainText = reader.Read(Buffer.from(chunk));
                writeStream.write(plainText);
                n++;
              }
              if (n === count) {
                writeStream.close();
                resolve(n);
              }
            } else {
              throw Error('src must be a "Buffer" object');
            }
          } catch (err: any) {
            reject(err);
          }
        });
      }
    } else {
      // dst is null
      const deriveKey = (await Promise.resolve(this.DecryptDeriveKey(src))); // as Uint8Array;
      const chunks: Buffer[] = [];
      if (isAbsolute(src.toString())) {
        // read stream -> Buffer
        const readStream = fs.createReadStream(src, { highWaterMark: _const.MaxPackageSize, start: 32 });
        let n = 0;
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new DecReader(config);
        return new Promise((resolve, reject) => {
          readStream.on('error', (err) => reject(err));
          readStream.on('data', (chunk) => {
            const plainText = reader.Read(Buffer.from(chunk));
            chunks.push(plainText);
            n++;
          });
          readStream.on('end', () => {
            resolve(Buffer.concat(chunks));
          });
        });
      } else {
        // Buffer -> Buffer
        let n = 0;
        const salt_offset = 32
        const config = new Config(deriveKey);
        config.setConfigDefaults();
        const reader = new DecReader(config);
        return new Promise((resolve, reject) => {
          try {
            if (Buffer.isBuffer(src)) {
              const count = Math.ceil((src.byteLength - salt_offset) / _const.MaxPackageSize);
              for (let i = 0; i < count; i++) {
                let s = i * _const.MaxPackageSize + salt_offset;
                let e = Math.min(src.byteLength, (i+1) * _const.MaxPackageSize + salt_offset);
                const chunk = src.subarray(s, e);
                const plainText = reader.Read(Buffer.from(chunk));
                chunks.push(plainText);
                n++;
              }
              if (n === count) {
                resolve(Buffer.concat(chunks));
              }
            } else {
              throw Error('src must be a "Buffer" object');
            }
          } catch (err: any) {
            reject(err);
          }
        });
      }
    }
  }
}
