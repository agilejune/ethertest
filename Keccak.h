#ifndef __KECCAK_H__
#define __KECCAK_H__

#include <cstdint>
#include <vector>

class Keccak
{
	std::vector<uint32_t> blocks;
	bool reset;
	uint32_t block;
	size_t start;
	size_t blockCount;
	size_t lastByteIndex;
	uint32_t outputBlocks;
	uint32_t s[50];

	void f();
public:
	Keccak(int bits);

	void update(const void *data, size_t size);
	std::vector<uint8_t> finalize();
};

#endif
