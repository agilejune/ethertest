#include "Keccak.h"
#include <cstring>

const static int KECCAK_PADDING[] = { 1, 256, 65536, 16777216 };
const static int SHIFT[] = { 0, 8, 16, 24 };
const static uint32_t RC[] = { 1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648 };

Keccak::Keccak(int bits) :
	reset(true),
	block(0),
	start(0),
    lastByteIndex(0),
	blockCount((1600-(bits<<1))>>5),
	outputBlocks(bits>>5)
{
	memset(s, 0, sizeof(s));
}

void Keccak::update(const void* data, size_t size)
{
	auto p = static_cast<const uint8_t*>(data);
	auto end = p + size;
    auto byteCount = blockCount << 2;

	while (p < end) {
        if (reset) {
            reset = false;
            blocks.resize(blockCount + 1, 0);
            blocks[0] = block;
            for (size_t i = 1; i < blockCount + 1; ++i) {
                blocks[i] = 0;
            }
        }
        size_t i;
        for (i = start; p < end && i < byteCount; ++p, ++i) {
            blocks[i >> 2] |= *p << SHIFT[i & 3];
        }

        lastByteIndex = i;
        if (i >= byteCount) {
            start = i - byteCount;
            block = blocks[blockCount];
            for (i = 0; i < blockCount; ++i) {
                s[i] ^= blocks[i];
            }
            f();
            reset = true;
        }
        else {
            start = i;
        }
    }
}

std::vector<uint8_t> Keccak::finalize()
{
    auto byteCount = blockCount << 2;
    auto i = lastByteIndex;
    blocks[i >> 2] |= KECCAK_PADDING[i & 3];
    if (lastByteIndex == byteCount) {
        blocks[0] = blocks[blockCount];
        for (i = 1; i < blockCount + 1; ++i) {
            blocks[i] = 0;
        }
    }
    blocks[blockCount - 1] |= 0x80000000;
    for (i = 0; i < blockCount; ++i) {
        s[i] ^= blocks[i];
    }
    f();

    std::vector<uint8_t> hash;
    for (size_t i = 0, j = 0; j < outputBlocks; ) {
        for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
            auto block = s[i];
            hash.push_back(block & 0xff);
            hash.push_back((block >> 8) & 0xff);
            hash.push_back((block >> 16) & 0xff);
            hash.push_back((block >> 24) & 0xff);
        }
        if (j % blockCount == 0) {
            f();
            i = 0;
        }
    }
    return hash;
}

void Keccak::f()
{
    for (size_t n = 0; n < 48; n += 2) {
        auto c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
        auto c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
        auto c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
        auto c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
        auto c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
        auto c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
        auto c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
        auto c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
        auto c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
        auto c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

        auto h = c8 ^ (c2 << 1 | c3 >> 31);
        auto l = c9 ^ (c3 << 1 | c2 >> 31);
        s[0] ^= h;
        s[1] ^= l;
        s[10] ^= h;
        s[11] ^= l;
        s[20] ^= h;
        s[21] ^= l;
        s[30] ^= h;
        s[31] ^= l;
        s[40] ^= h;
        s[41] ^= l;
        h = c0 ^ (c4 << 1 | c5 >> 31);
        l = c1 ^ (c5 << 1 | c4 >> 31);
        s[2] ^= h;
        s[3] ^= l;
        s[12] ^= h;
        s[13] ^= l;
        s[22] ^= h;
        s[23] ^= l;
        s[32] ^= h;
        s[33] ^= l;
        s[42] ^= h;
        s[43] ^= l;
        h = c2 ^ (c6 << 1 | c7 >> 31);
        l = c3 ^ (c7 << 1 | c6 >> 31);
        s[4] ^= h;
        s[5] ^= l;
        s[14] ^= h;
        s[15] ^= l;
        s[24] ^= h;
        s[25] ^= l;
        s[34] ^= h;
        s[35] ^= l;
        s[44] ^= h;
        s[45] ^= l;
        h = c4 ^ (c8 << 1 | c9 >> 31);
        l = c5 ^ (c9 << 1 | c8 >> 31);
        s[6] ^= h;
        s[7] ^= l;
        s[16] ^= h;
        s[17] ^= l;
        s[26] ^= h;
        s[27] ^= l;
        s[36] ^= h;
        s[37] ^= l;
        s[46] ^= h;
        s[47] ^= l;
        h = c6 ^ (c0 << 1 | c1 >> 31);
        l = c7 ^ (c1 << 1 | c0 >> 31);
        s[8] ^= h;
        s[9] ^= l;
        s[18] ^= h;
        s[19] ^= l;
        s[28] ^= h;
        s[29] ^= l;
        s[38] ^= h;
        s[39] ^= l;
        s[48] ^= h;
        s[49] ^= l;

        auto b0 = s[0];
        auto b1 = s[1];
        auto b32 = s[11] << 4 | s[10] >> 28;
        auto b33 = s[10] << 4 | s[11] >> 28;
        auto b14 = s[20] << 3 | s[21] >> 29;
        auto b15 = s[21] << 3 | s[20] >> 29;
        auto b46 = s[31] << 9 | s[30] >> 23;
        auto b47 = s[30] << 9 | s[31] >> 23;
        auto b28 = s[40] << 18 | s[41] >> 14;
        auto b29 = s[41] << 18 | s[40] >> 14;
        auto b20 = s[2] << 1 | s[3] >> 31;
        auto b21 = s[3] << 1 | s[2] >> 31;
        auto b2 = s[13] << 12 | s[12] >> 20;
        auto b3 = s[12] << 12 | s[13] >> 20;
        auto b34 = s[22] << 10 | s[23] >> 22;
        auto b35 = s[23] << 10 | s[22] >> 22;
        auto b16 = s[33] << 13 | s[32] >> 19;
        auto b17 = s[32] << 13 | s[33] >> 19;
        auto b48 = s[42] << 2 | s[43] >> 30;
        auto b49 = s[43] << 2 | s[42] >> 30;
        auto b40 = s[5] << 30 | s[4] >> 2;
        auto b41 = s[4] << 30 | s[5] >> 2;
        auto b22 = s[14] << 6 | s[15] >> 26;
        auto b23 = s[15] << 6 | s[14] >> 26;
        auto b4 = s[25] << 11 | s[24] >> 21;
        auto b5 = s[24] << 11 | s[25] >> 21;
        auto b36 = s[34] << 15 | s[35] >> 17;
        auto b37 = s[35] << 15 | s[34] >> 17;
        auto b18 = s[45] << 29 | s[44] >> 3;
        auto b19 = s[44] << 29 | s[45] >> 3;
        auto b10 = s[6] << 28 | s[7] >> 4;
        auto b11 = s[7] << 28 | s[6] >> 4;
        auto b42 = s[17] << 23 | s[16] >> 9;
        auto b43 = s[16] << 23 | s[17] >> 9;
        auto b24 = s[26] << 25 | s[27] >> 7;
        auto b25 = s[27] << 25 | s[26] >> 7;
        auto b6 = s[36] << 21 | s[37] >> 11;
        auto b7 = s[37] << 21 | s[36] >> 11;
        auto b38 = s[47] << 24 | s[46] >> 8;
        auto b39 = s[46] << 24 | s[47] >> 8;
        auto b30 = s[8] << 27 | s[9] >> 5;
        auto b31 = s[9] << 27 | s[8] >> 5;
        auto b12 = s[18] << 20 | s[19] >> 12;
        auto b13 = s[19] << 20 | s[18] >> 12;
        auto b44 = s[29] << 7 | s[28] >> 25;
        auto b45 = s[28] << 7 | s[29] >> 25;
        auto b26 = s[38] << 8 | s[39] >> 24;
        auto b27 = s[39] << 8 | s[38] >> 24;
        auto b8 = s[48] << 14 | s[49] >> 18;
        auto b9 = s[49] << 14 | s[48] >> 18;

        s[0] = b0 ^ ~b2 & b4;
        s[1] = b1 ^ ~b3 & b5;
        s[10] = b10 ^ ~b12 & b14;
        s[11] = b11 ^ ~b13 & b15;
        s[20] = b20 ^ ~b22 & b24;
        s[21] = b21 ^ ~b23 & b25;
        s[30] = b30 ^ ~b32 & b34;
        s[31] = b31 ^ ~b33 & b35;
        s[40] = b40 ^ ~b42 & b44;
        s[41] = b41 ^ ~b43 & b45;
        s[2] = b2 ^ ~b4 & b6;
        s[3] = b3 ^ ~b5 & b7;
        s[12] = b12 ^ ~b14 & b16;
        s[13] = b13 ^ ~b15 & b17;
        s[22] = b22 ^ ~b24 & b26;
        s[23] = b23 ^ ~b25 & b27;
        s[32] = b32 ^ ~b34 & b36;
        s[33] = b33 ^ ~b35 & b37;
        s[42] = b42 ^ ~b44 & b46;
        s[43] = b43 ^ ~b45 & b47;
        s[4] = b4 ^ ~b6 & b8;
        s[5] = b5 ^ ~b7 & b9;
        s[14] = b14 ^ ~b16 & b18;
        s[15] = b15 ^ ~b17 & b19;
        s[24] = b24 ^ ~b26 & b28;
        s[25] = b25 ^ ~b27 & b29;
        s[34] = b34 ^ ~b36 & b38;
        s[35] = b35 ^ ~b37 & b39;
        s[44] = b44 ^ ~b46 & b48;
        s[45] = b45 ^ ~b47 & b49;
        s[6] = b6 ^ ~b8 & b0;
        s[7] = b7 ^ ~b9 & b1;
        s[16] = b16 ^ ~b18 & b10;
        s[17] = b17 ^ ~b19 & b11;
        s[26] = b26 ^ ~b28 & b20;
        s[27] = b27 ^ ~b29 & b21;
        s[36] = b36 ^ ~b38 & b30;
        s[37] = b37 ^ ~b39 & b31;
        s[46] = b46 ^ ~b48 & b40;
        s[47] = b47 ^ ~b49 & b41;
        s[8] = b8 ^ ~b0 & b2;
        s[9] = b9 ^ ~b1 & b3;
        s[18] = b18 ^ ~b10 & b12;
        s[19] = b19 ^ ~b11 & b13;
        s[28] = b28 ^ ~b20 & b22;
        s[29] = b29 ^ ~b21 & b23;
        s[38] = b38 ^ ~b30 & b32;
        s[39] = b39 ^ ~b31 & b33;
        s[48] = b48 ^ ~b40 & b42;
        s[49] = b49 ^ ~b41 & b43;

        s[0] ^= RC[n];
        s[1] ^= RC[n + 1];
    }
}
