#ifndef MXBITSET_H
#define MXBITSET_H

#pragma warning(disable : 4237)

#include "mxtypes.h"

#include <assert.h>
#include <limits.h> // CHAR_BIT

template <size_t N>
class MxBitset {
public:
	MxBitset() { Tidy(); }

	// SIZE 0x08
	class Reference {
		friend class MxBitset<N>;

	public:
		Reference& Flip()
		{
			m_bitset->Flip(m_offset);
			return (*this);
		}
		bool operator~() const { return (!m_bitset->Test(m_offset)); }
		operator bool() const { return (m_bitset->Test(m_offset)); }

	private:
		Reference(MxBitset<N>& p_bitset, size_t p_offset) : m_bitset(&p_bitset), m_offset(p_offset) {}
		MxBitset<N>* m_bitset; // 0x00
		size_t m_offset;       // 0x04
	};

	Reference operator[](size_t p_bit) { return (Reference(*this, p_bit)); }

	MxBitset<N>& Flip(size_t p_bit)
	{
		if (N <= p_bit) {
			Xran();
		}
		m_blocks[p_bit / e_bitsPerBlock] ^= 1 << p_bit % e_bitsPerBlock;
		return (*this);
	}

	size_t Count()
	{
		// debug only, intentionally unimplemented
		return 0;
	}

	bool Test(MxU32 p_bit)
	{
		if (p_bit >= N) {
			Xran();
		}

		return (m_blocks[p_bit / e_bitsPerBlock] & (1 << p_bit % e_bitsPerBlock)) != 0;
	}

	MxU32 Size() const { return N; }

private:
	void Tidy(MxU32 p_value = 0)
	{
		for (MxS32 i = e_blocksRequired; i >= 0; --i) {
			m_blocks[i] = p_value;
		}

		// No need to trim if all bits were zeroed out
		if (p_value != 0) {
			Trim();
		}
	}

	// Apply bit mask to most significant block
	void Trim()
	{
		if (N % e_bitsPerBlock != 0) {
			m_blocks[e_blocksRequired] &= ((1 << (N % e_bitsPerBlock)) - 1);
		}
	}

	void Xran() { assert("invalid MxBitset<N> position" == NULL); }

	// Not a real enum. This is how STL BITSET defines these constants.
	enum {
		e_bitsPerBlock = CHAR_BIT * sizeof(MxU32),
		e_blocksRequired = N == 0 ? 0 : (N - 1) / e_bitsPerBlock
	};

	MxU32 m_blocks[e_blocksRequired + 1]; // 0x00
};

#endif // MXBITSET_H
