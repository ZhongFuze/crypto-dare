import DARE from '../index';

// jest.setTimeout(10000)

it('EncDeriveKey', async () => {
  let src = 'README.md';
  let dst = 'README.md.enc';
  let password = '012345678901234567890';
  let dare = new DARE(password, src, dst);
  const deriveKey = await Promise.resolve(dare.EncryptDeriveKey());
  // use deriveKey ...
});

it('DecDeriveKey', async () => {
  let src = 'README.md.enc';
  let dst = 'README.md.dec';
  let password = '012345678901234567890';
  let dare = new DARE(password, src, dst);
  const deriveKey = await Promise.resolve(dare.DecryptDeriveKey());
  // use deriveKey ...
});

it('Encrypt', async () => {
  let src = 'README.md';
  let dst = 'README.md.enc';
  let password = '012345678901234567890';
  let dare = new DARE(password, src, dst);
  const nn = await Promise.resolve(dare.Encrypt());
  console.log('number of package:', nn);
});

it('Decrypt', async () => {
  let src = 'README.md.enc';
  let dst = 'README2.md';
  let password = '012345678901234567890';
  let dare = new DARE(password, src, dst);
  const nn = await Promise.resolve(dare.Decrypt());
  console.log('number of package:', nn);
});
