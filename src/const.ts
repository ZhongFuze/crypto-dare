const KeySize = 1;
const HeaderSize = 16;
const MaxPayloadSize = 1 << 16;
const TagSize = 16; // 65536
const ReadSize = 32 * 1024;
const MaxPackageSize = HeaderSize + MaxPayloadSize + TagSize;
const MaxDecryptedSize = 1 << 48; // (32 TB)
const MaxEncryptedSize = MaxDecryptedSize + (((HeaderSize + TagSize) * 1) << 32);
export { KeySize, HeaderSize, MaxPayloadSize, TagSize, ReadSize, MaxPackageSize };
