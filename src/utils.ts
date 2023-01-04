var toUint16 = function(arr: ArrayBuffer, endianness: string): number {
  var view = new DataView(arr)
  var number = view.getUint16(0, endianness === 'LE')
  return number
}

var toUint32 = function(arr: ArrayBuffer, endianness: string): number {
  var view = new DataView(arr)
  var number = view.getUint32(0, endianness === 'LE')
  return number
}

var toByte16 = function(num: number, endianness: string): ArrayBuffer {
  var arr = new ArrayBuffer(2) // an Uint16 takes 2 bytes 0-65535
  var view = new DataView(arr)
  view.setUint16(0, num, endianness === 'LE') // byteOffset = 0; litteEndian = true
  return arr
}

var toByte32 = function(num: number, endianness: string): ArrayBuffer {
  var arr = new ArrayBuffer(4) // an Uint32 takes 4 bytes
  var view = new DataView(arr)
  view.setUint32(0, num, endianness === 'LE')
  return arr
}

var toBuffer = function(arr: ArrayBuffer): Buffer {
  const buf = Buffer.alloc(arr.byteLength)
  const view = new Uint8Array(arr)
  for (let i = 0; i < buf.length; ++i) {
      buf[i] = view[i]
  }
  return buf
}

var toArrayBuffer = function(buf: Buffer): ArrayBuffer {
  const arr = new ArrayBuffer(buf.length)
  const view = new Uint8Array(arr)
  for (let i = 0; i < buf.length; ++i) {
      view[i] = buf[i]
  }
  return arr
}

export function PutUint16LE(num: number): Buffer {
  return toBuffer(toByte16(num, 'LE'))
}

export function Uint16LE(buf: Buffer): number {
  return toUint16(toArrayBuffer(buf), 'LE')
}

export function PutUint32LE(num: number): Buffer {
  return toBuffer(toByte32(num, 'LE'))
}

export function Uint32LE(buf: Buffer): number {
  return toUint32(toArrayBuffer(buf), 'LE')
}
