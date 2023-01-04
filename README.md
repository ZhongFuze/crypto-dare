# crypto-dare

```typescript
import * as DARE from 'crypto-dare';

let src = 'Your Origin File (Input)'; // input.txt
let dst = 'Your Encrypt File (Output)'; // input.enc
let password = '012345678901234567890';
let dare = new DARE(password, src, dst);
const nn = await Promise.resolve(dare.Encrypt());
console.log('Number of package:', nn);
```

```typescript
import * as DARE from 'crypto-dare';

let src = 'Your Encrypt File (Input)'; // input.enc
let dst = 'Your Decrypt File (Output)'; // output.dec
let password = '012345678901234567890';
let dare = new DARE(password, src, dst);
const nn = await Promise.resolve(dare.Decrypt());
console.log('number of package:', nn);
```

## Introduce

Storing data securely is a common problem -- especially on untrusted remote storage. One solution to this problem is cryptography. Encrypt data before storing it to ensure data confidentiality. Unfortunately, encrypting data is not enough to prevent more sophisticated attacks. Anyone with access to stored data can attempt to manipulate it -- even if it's encrypted.

To prevent such attacks, data must be encrypted in a tamper-resistant manner. This means an attacker should not be able to:

- Read stored data - this is achieved through modern encryption algorithms.
- Modify data by changing parts of encrypted data.
- Rearrange or reorder partially encrypted data.

Authenticated encryption schemes (AE) - such as AES-GCM - encrypt and authenticate data.
Detect any modification to encrypted data (ciphertext) while decrypting the data.
But even AE schemes alone are not enough to prevent various data manipulations.

All modern AE schemes produce an authentication tag, which is verified after the ciphertext is decrypted. If a large amount of data is decrypted, it is not always possible to buffer all the decrypted data until the authentication tag is verified. Returning unauthenticated data has the same problems as unauthenticated encrypted data.

Breaking the data into small **chunks** solves the problem of delayed authentication checks, but introduces a new problem. Blocks can be reordered - for example swapping blocks 1 and 2 - because each block is encrypted individually. Therefore, the order of the blocks must somehow be encoded into the blocks themselves to be able to detect rearranging any number of blocks.

This project specifies a format for encrypting/decrypting arbitrary data streams and provides recommendations on how to use and implement Data at Rest Encryption (DARE).
Additionally, the project provides a reference implementation in **TypeScript**.

## Application

DARE was designed with simplicity and efficiency in mind.
It combines a modern AE scheme with a very simple reordering protection mechanism to build a tamper-resistant encryption scheme.
DARE can be used to encrypt files, backups and even large object storage systems.

Its main properties are:

- Rely on the security and performance of modern AEAD ciphers
- Low overhead - encryption increases data size by about 0.05%
- Support for long data streams - up to 256 TB under the same key
- Random access - arbitrary sequences/ranges can be decrypted independently

Install: `npm install crypto-dare`

## Data At Rest Encryption (DARE)

DARE specifies how to split an arbitrary data stream into small chunks (packages)
and concatenate them into a tamper-proof chain. Tamper-proof means that an attacker
is not able to:

- decrypt one or more packages.
- modify the content of one or more packages.
- reorder/rearrange one or more packages.

An attacker is defined as somebody who has full access to the encrypted data
but not to the encryption key. An attacker can also act as storage provider.

### 1. Keys

AES-256_GCM equire a 32 byte key. The key **must** be unique for one encrypted data stream.
Reusing a key **compromises** some security properties provided by DARE.

#### 1.2 Key Derivation

DARE needs a unique encryption key per data stream. The best approach to ensure that the keys
are unique is to derive every encryption key from a master key.
Therefore a key derivation function (KDF) - e.g. HKDF can be used. The master key itself may be derived from a password using functions like **scrypt**. Deriving those keys is the responsibility of the
users of DARE.

#### 1.2 Generating random values

DARE does not require random values which are indistinguishable from a truly random bit sequence.
However, a random value **must** never be repeated. Therefore it is **recommended** to use a
cryptographically secure pseudorandom number generator (CSPRNG) to generate random values.

### 2. Package Format

DARE splits an arbitrary data stream into a sequence of packages. Each package is
encrypted separately. A package consists of a header, a payload and an authentication
tag.

| Header   | Payload        | Tag      |
| -------- | -------------- | -------- |
| 16 bytes | 1 byte - 64 KB | 16 bytes |

The header contains information about the package. It consists of:

| Version | Cipher suite | Payload size     | Sequence number  | nonce   |
| ------- | ------------ | ---------------- | ---------------- | ------- |
| 1 byte  | 1 byte       | 2 bytes / uint16 | 4 bytes / uint32 | 8 bytes |

The first byte specifies the version of the format and is equal to 0x10 for DARE
version 1.0. The second byte specifies the cipher used to encrypt the package.

### 3. Encryption

The nonce **should** be generated randomly once
at the beginning of the encryption process and repeated in every header.

The sequence number is the sequence number of the previous package plus 1. The sequence number
**must** be a monotonically increasing number within one sequence of packages. The sequence number
of the first package is **always** 0.

The payload field is the length of the plaintext in bytes minus 1. The encryption process is
defined as following:

```
header[0]       = 0x10
header[1]       = {AES-256_GCM, CHACHA20_POLY1305}
header[2:4]     = little_endian( len(plaintext) - 1 )
header[4:8]     = little_endian( sequence_number )
header[8:16]    = nonce

payload || tag  = ENC(key, header[4:16], plaintext, header[0:4])

sequence_number = sequence_number + 1
```

### 4. Decryption

1. Verify that the header
2. Verify that the sequence number of the packages matches the expected sequence number.
3. Verify that the nonce matches. Compare nonce **must** happen in constant time.
4. Verify that the authentication tag at the end of the package is equal to the authentication tag
   computed while decrypting the package.

The decryption is defined as following:

```
header[0]                          != 0x10                            => err_unsupported_version
header[1]                          != {AES-256_GCM,CHACHA20_POLY1305} => err_unsupported_cipher
little_endian_uint32(header[4:8])  != expected_sequence_number        => err_package_out_of_order

payload_size      := little_endian_uint32(header[2:4]) + 1
plaintext || tag  := DEC(key, header[4:16], ciphertext, header[0:4])

CTC(ciphertext[len(plaintext) : len(plaintext) + 16], tag) != 1       => err_tag_mismatch

expected_sequence_number = expected_sequence_number + 1
```
