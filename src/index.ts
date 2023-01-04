import * as fs from 'fs'
import * as crypto from 'crypto'
import * as scrypt from 'scrypt-js'

import * as _const from './const'
import Config from './config'
import EncReader from './encrypt'
import DecReader from './decrypt'

type BinaryLike = string | NodeJS.ArrayBufferView;

export default class DARE {
  EncryptDeriveKey(password: string, src: string, dst: string) {
    let pswd = Buffer.from(password.normalize('NFKC'))
    let salt = crypto.randomBytes(32)
    const N = 32768, r = 16, p = 1, dkLen = 32
    const ws = fs.createWriteStream(dst)
    ws.write(salt)
    ws.close()
    return new Promise((resolve, reject) => {
      ws.on('finish', function() {
        const key = scrypt.syncScrypt(pswd, salt, N, r, p, dkLen)
        resolve(key)
      })
      ws.on('error', err => reject(err))
    })
  }
  DecryptDeriveKey(password: string, src: string, dst: string) {
    let pswd = Buffer.from(password.normalize('NFKC'))
    const N = 32768, r = 16, p = 1, dkLen = 32
    let data: Buffer[] = []
    const rs = fs.createReadStream(src, {start: 0, end: 31})
    return new Promise((resolve, reject) => {
      rs.on('data', (chunk) => {
        data.push(Buffer.from(chunk))
      });
      rs.on('end', () => {
        let salt = Buffer.concat(data)
        const key = scrypt.syncScrypt(pswd, salt, N, r, p, dkLen)
        resolve(key)
      });
      rs.on('error', err => reject(err))
    });
  }
  Encrypt(deriveKey: BinaryLike, src: string, dst: string) {
    const readStream = fs.createReadStream(src, {highWaterMark: _const.MaxPayloadSize, start: 0})
    const writeStream = fs.createWriteStream(dst, {flags: 'a'})
    let n = 0
    let config = new Config(deriveKey)
    config.setConfigDefaults()
    let reader = new EncReader(config)
    return new Promise((resolve, reject) => {
      readStream.on('error', err => reject(err));
      readStream.on('data', (chunk) => {
        let cipherText = reader.Read(Buffer.from(chunk))
        writeStream.write(cipherText)
        n++
      });
      readStream.on('end', () => {
        writeStream.close()
        resolve(n)
      });
    });
  }
  Decrypt(deriveKey: BinaryLike, src: string, dst: string) {
    const readStream = fs.createReadStream(src, {highWaterMark: _const.MaxPackageSize, start: 32})
    const writeStream = fs.createWriteStream(dst)
    let n = 0
    let config = new Config(deriveKey)
    config.setConfigDefaults()
    let reader = new DecReader(config)
    return new Promise((resolve, reject) => {
      readStream.on('error', err => reject(err));
      readStream.on('data', (chunk) => {
        let plainText = reader.Read(Buffer.from(chunk))
        writeStream.write(plainText)
        n++
      })
      readStream.on('end', () => {
        writeStream.close()
        resolve(n)
      })
    })

  }
  readFile(filename: string): string {
    let content = fs.readFileSync(filename)
    return content.toString()
  }
  getSHA(filename: string) {
    return new Promise((resolve, reject) => {
      let hash = crypto.createHash("sha1")
      let stream = fs.createReadStream(filename)
      stream.on("error", err => reject(err))
      stream.on("data", chunk => hash.update(chunk))
      stream.on("end", () => resolve(hash.digest("hex")))
    })
  }
}
