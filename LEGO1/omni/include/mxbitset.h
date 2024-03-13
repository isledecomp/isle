#ifndef MXBITSET_H
#define MXBITSET_H

#pragma warning(disable : 4237)

#include "mxtypes.h"

#include <assert.h>
#include <limits.h> // CHAR_BIT

template <size_t N>
class MxBitset {
public:
	MxBitset() { _Tidy(); }

	class reference {
		friend class MxBitset<N>;

	public:
		reference& flip()
		{
			m_bitset->flip(m_offset);
			return (*this);
		}
		bool operator~() const { return (!m_bitset->test(m_offset)); }
		operator bool() const { return (m_bitset->test(m_offset)); }

	private:
		reference(MxBitset<N>& _X, size_t _P) : m_bitset(&_X), m_offset(_P) {}
		MxBitset<N>* m_bitset;
		size_t m_offset;
	};

	reference operator[](size_t p_bit) { return (reference(*this, p_bit)); }

	MxBitset<N>& flip(size_t p_bit)
	{
		if (N <= p_bit) {
			_Xran();
		}
		m_blocks[p_bit / _bits_per_block] ^= 1 << p_bit % _bits_per_block;
		return (*this);
	}

	size_t count()
	{
		// debug only
		return 0;
	}

	bool test(MxU32 p_bit)
	{
		if (p_bit >= N) {
			_Xran();
		}

		return (m_blocks[p_bit / _bits_per_block] & (1 << p_bit % _bits_per_block)) != 0;
	}

	MxU32 size() const { return N; }

private:
	void _Tidy(MxU32 p_value = 0)
	{
		for (MxS32 i = _blocks_required; i >= 0; --i) {
			m_blocks[i] = p_value;
		}

		// No need to trim if all bits were zeroed out
		if (p_value != 0) {
			_Trim();
		}
	}

	// Apply bit mask to most significant block
	void _Trim()
	{
		if (N % _bits_per_block != 0) {
			m_blocks[_blocks_required] &= ((1 << (N % _bits_per_block)) - 1);
		}
	}

	void _Xran() { assert("invalid MxBitset<N> position" == NULL); }

	enum {
		_bits_per_block = CHAR_BIT * sizeof(MxU32),
		_blocks_required = N == 0 ? 0 : (N - 1) / _bits_per_block
	};

	MxU32 m_blocks[_blocks_required + 1]; // 0x0
};

#endif // MXBITSET_H
