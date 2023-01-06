import DARE from '../index';
import * as path from 'path';
import * as fs from 'fs';
jest.setTimeout(10000);

function readFile(filename: string): Buffer {
  const content = fs.readFileSync(filename);
  return content;
}

function writeFile(filename: string, content: Buffer): void {
  fs.writeFileSync(filename, content);
}

it('encrypt derive key: fs.PathLike', async () => {
  const dst = path.join(process.cwd(), 'README.md.enc');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const deriveKey = await Promise.resolve(dare.EncryptDeriveKey(dst));
  console.log(deriveKey);
  // use deriveKey ...
});

it('encrypt derive key: Buffer', async () => {
  const dst = path.join(process.cwd(), 'README.md.enc');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const [deriveKey2, salt] = await Promise.resolve(dare.EncryptDeriveKey());
  console.log(deriveKey2, salt);
  writeFile(dst, salt);
  // use deriveKey ...
});

it('decrypt derive key: fs.PathLike', async () => {
  const src = path.join(process.cwd(), 'README.md.enc'); // fs.PathLike
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const deriveKey = await Promise.resolve(dare.DecryptDeriveKey(src));
  console.log(deriveKey);
  // use deriveKey ...
});

it('decrypt derive key: Buffer', async () => {
  const src = readFile(path.join(process.cwd(), 'README.md.enc')); // Buffer
  const password = '012345678901234567890';
  const dare = new DARE(password);
  await dare
    .DecryptDeriveKey(src)
    .then((deriveKey) => {
      // use deriveKey ...
      console.log(deriveKey);
    })
    .catch((err) => {
      console.error(err.message);
    });
});

it('Encrypt: path -> path', async () => {
  const src = path.join(process.cwd(), 'README.md');
  const dst = path.join(process.cwd(), 'README.md.enc');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const nn = await Promise.resolve(dare.Encrypt(src, dst));
  console.log('number of package:', nn);
});

it('Decrypt: path -> path', async () => {
  const src = path.join(process.cwd(), 'README.md.enc');
  const dst = path.join(process.cwd(), 'README.md.dec');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const nn = await Promise.resolve(dare.Decrypt(src, dst));
  console.log('number of package:', nn);
});

it('Encrypt: fs.PathLike -> fs.PathLike', async () => {
  const src = path.join(process.cwd(), 'README.md');
  const dst = path.join(process.cwd(), 'README.md.enc');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const nn = await Promise.resolve(dare.Encrypt(src, dst));
  console.log('number of package:', nn);
});

it('Decrypt: Buffer -> fs.PathLike', async () => {
  const src = readFile(path.join(process.cwd(), 'README.md.enc'));
  const dst = path.join(process.cwd(), 'README.md.dec');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const nn = await Promise.resolve(dare.Decrypt(src, dst));
  console.log('number of package:', nn);
});

it('Decrypt: fs.PathLike -> Buffer', async () => {
  const src = path.join(process.cwd(), 'README.md.enc');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const dst = await Promise.resolve(dare.Decrypt(src));
  console.log('Decrypt content is:', dst.toString());
});

it('Encrypt/Decrypt: Buffer -> Buffer', async () => {
  const src = Buffer.from('Hello world');
  const password = '012345678901234567890';
  const dare = new DARE(password);
  const encrypt = await Promise.resolve(dare.Encrypt(src));
  const dst = await Promise.resolve(dare.Decrypt(encrypt));
  console.log('Origin content is:', dst.toString());
  console.log('Encrypt content is:', encrypt.toString());
  console.log('Decrypt content is:', dst.toString());
});

// import DARE from 'crypto-dare';

// it('Encrypt', async () => {
//   let src = 'README.md'; // input.txt
//   let dst = 'README.md.enc'; // input.enc
//   let password = '012345678901234567890';
//   let dare = new DARE(password, src, dst);
//   const nn = await Promise.resolve(dare.Encrypt());
//   console.log('Number of package:', nn);
// })

// it('Decrypt', async () => {
//   let src = 'README.md.enc';
//   let dst = 'README2.md';
//   let password = '012345678901234567890';
//   let dare = new DARE(password, src, dst);
//   const nn = await Promise.resolve(dare.Decrypt());
//   console.log('number of package:', nn);
// });
