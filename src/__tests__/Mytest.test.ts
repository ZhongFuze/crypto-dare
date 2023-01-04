// import DARE from 'crypto-dare';

// it('Encrypt', async () => {
//   // let dare = new DARE();
//   let src = 'README.md';
//   let dst = 'README.md.enc';
//   // let src = 'README.md'
//   // let dst = 'README.md.enc'
//   let password = '012345678901234567890';
//   let deriveKey = (await Promise.resolve(dare.EncryptDeriveKey(password, src, dst))) as Uint8Array;
//   const nn = await Promise.resolve(dare.Encrypt(deriveKey, src, dst));
//   console.log('number of package:', nn);
// });

// it('Decrypt', async () => {
//   let dare = new DARE();
//   let src = 'README.md.enc';
//   let dst = 'README2.md';
//   let password = '012345678901234567890';
//   let deriveKey = (await Promise.resolve(dare.DecryptDeriveKey(password, src, dst))) as Uint8Array;
//   const nn = await Promise.resolve(dare.Decrypt(deriveKey, src, dst));
//   console.log('number of package:', nn);
// });
