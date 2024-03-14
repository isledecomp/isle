#ifndef MXMEMORYPOOL_H
#define MXMEMORYPOOL_H

#include "decomp.h"
#include "mxbitset.h"
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

#ifdef _DEBUG
			// TODO: This is actually some debug print function, but
			// we just need any func with variatic args to eliminate diff noise.
			printf("Get> %d pool: busy %d blocks\n", m_blockSize, m_blockRef.Count());
#endif

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

#ifdef _DEBUG
	printf("Release> %d pool: busy %d blocks\n", m_blockSize, m_blockRef.Count());
#endif
}

#endif // MXMEMORYPOOL_H
