import DARE from '../index'

// jest.setTimeout(10000)

it('Get SHA', async () => {
  let dare = new DARE()
  let filename = 'src/index.ts'
  const cast = await Promise.resolve(dare.getSHA(filename))
  console.log('file:', filename, 'SHA is: ', cast)
})

it('EncDeriveKey', async () => {
  let dare = new DARE()
  let src = 'README.md'
  let dst = 'README.md.enc'
  let password = '012345678901234567890'
  const deriveKey = await Promise.resolve(dare.EncryptDeriveKey(password, src, dst))
  // use deriveKey ...
})

it('DecDeriveKey', async () => {
  let dare = new DARE()
  let src = 'README.md.enc'
  let dst = 'README.md.dec'
  let password = '012345678901234567890'
  const deriveKey = await Promise.resolve(dare.DecryptDeriveKey(password, src, dst))
  // use deriveKey ...
})

it('Encrypt', async () => {
  let dare = new DARE()
  let src = 'README.md'
  let dst = 'README.md.enc'
  let password = '012345678901234567890'
  let deriveKey = await Promise.resolve(dare.EncryptDeriveKey(password, src, dst)) as Uint8Array
  const nn = await Promise.resolve(dare.Encrypt(deriveKey, src, dst))
  console.log('number of package:', nn)
})

it('Decrypt', async () => {
  let dare = new DARE()
  let src = 'README.md.enc'
  let dst = 'README.md.dec'
  let password = '012345678901234567890'
  let deriveKey = await Promise.resolve(dare.DecryptDeriveKey(password, src, dst)) as Uint8Array
  const nn = await Promise.resolve(dare.Decrypt(deriveKey, src, dst))
  console.log('number of package:', nn)
})
