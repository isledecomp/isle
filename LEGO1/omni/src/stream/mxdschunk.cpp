#include "mxdschunk.h"

DECOMP_SIZE_ASSERT(MxDSChunk, 0x1c);

// FUNCTION: LEGO1 0x100be050
// FUNCTION: BETA10 0x10147290
MxDSChunk::MxDSChunk()
{
	m_data = NULL;
	m_flags = 0;
	m_objectId = -1;
	m_time = 0;
	m_length = 0;
}

// FUNCTION: LEGO1 0x100be170
// FUNCTION: BETA10 0x10147330
MxDSChunk::~MxDSChunk()
{
	if (m_flags & DS_CHUNK_BIT1) {
		delete[] m_data;
	}
}

// FUNCTION: LEGO1 0x100be1e0
// FUNCTION: BETA10 0x101473c5
MxU32 MxDSChunk::GetHeaderSize()
{
	return 0x0e;
}
