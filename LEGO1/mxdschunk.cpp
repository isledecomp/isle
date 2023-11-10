#include "mxdschunk.h"

DECOMP_SIZE_ASSERT(MxDSChunk, 0x1c);

// OFFSET: LEGO1 0x100be050
MxDSChunk::MxDSChunk()
{
	m_flags = 0;
	m_data = NULL;
	m_unk0c = -1;
	m_time = 0;
	m_length = 0;
}

// OFFSET: LEGO1 0x100be170
MxDSChunk::~MxDSChunk()
{
	if (m_flags & Flag_Bit1) {
		delete[] m_data;
	}
}
