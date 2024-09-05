#ifndef MXMEMORYPOOL_H
#define MXMEMORYPOOL_H

#include "decomp.h"
#include "mxbitset.h"
#include "mxdebug.h"
#include "mxtypes.h"

#include <assert.h>

template <size_t BS, size_t NB>
class MxMemoryPool {
public:
	MxMemoryPool() : m_pool(NULL), m_blockSize(BS) {}
	~MxMemoryPool() { delete[] m_pool; }

	MxResult Allocate();
	MxU8* Get();
	void Release(MxU8*);

	MxU32 GetPoolSize() const { return m_blockRef.Size(); }

private:
	MxU8* m_pool;            // 0x00
	MxU32 m_blockSize;       // 0x04
	MxBitset<NB> m_blockRef; // 0x08
};

template <size_t BS, size_t NB>
MxResult MxMemoryPool<BS, NB>::Allocate()
{
	assert(m_pool == NULL);
	assert(m_blockSize);
	assert(m_blockRef.Size());

	m_pool = new MxU8[GetPoolSize() * m_blockSize * 1024];
	assert(m_pool);

	return m_pool ? SUCCESS : FAILURE;
}

template <size_t BS, size_t NB>
MxU8* MxMemoryPool<BS, NB>::Get()
{
	assert(m_pool != NULL);
	assert(m_blockSize);
	assert(m_blockRef.Size());

	for (MxU32 i = 0; i < GetPoolSize(); i++) {
		if (!m_blockRef[i]) {
			m_blockRef[i].Flip();

			MxTrace("Get> %d pool: busy %d blocks\n", m_blockSize, m_blockRef.Count());

			return &m_pool[i * m_blockSize * 1024];
		}
	}

	return NULL;
}

template <size_t BS, size_t NB>
void MxMemoryPool<BS, NB>::Release(MxU8* p_buf)
{
	assert(m_pool != NULL);
	assert(m_blockSize);
	assert(m_blockRef.Size());

	MxU32 i = (MxU32) (p_buf - m_pool) / (m_blockSize * 1024);

	assert(i >= 0 && i < GetPoolSize());
	assert(m_blockRef[i]);

	if (m_blockRef[i]) {
		m_blockRef[i].Flip();
	}

	MxTrace("Release> %d pool: busy %d blocks\n", m_blockSize, m_blockRef.Count());
}

// TEMPLATE: BETA10 0x101464a0
// MxMemoryPool<64,22>::MxMemoryPool<64,22>

// TEMPLATE: LEGO1 0x100b9100
// TEMPLATE: BETA10 0x10146590
// MxMemoryPool<64,22>::~MxMemoryPool<64,22>

// TEMPLATE: BETA10 0x101465c0
// MxMemoryPool<128,2>::MxMemoryPool<128,2>

// TEMPLATE: LEGO1 0x100b9110
// TEMPLATE: BETA10 0x101466b0
// MxMemoryPool<128,2>::~MxMemoryPool<128,2>

// TEMPLATE: BETA10 0x10146780
// MxMemoryPool<64,22>::Allocate

// TEMPLATE: BETA10 0x101468a0
// MxMemoryPool<64,22>::GetPoolSize

// TEMPLATE: BETA10 0x101468d0
// MxMemoryPool<128,2>::Allocate

// TEMPLATE: BETA10 0x101469f0
// MxMemoryPool<128,2>::GetPoolSize

// TEMPLATE: BETA10 0x10158610
// MxMemoryPool<64,22>::Release

// TEMPLATE: BETA10 0x101589e0
// MxMemoryPool<128,2>::Release

// TEMPLATE: BETA10 0x10158e50
// MxMemoryPool<64,22>::Get

// TEMPLATE: BETA10 0x10158f90
// MxMemoryPool<128,2>::Get

#endif // MXMEMORYPOOL_H
