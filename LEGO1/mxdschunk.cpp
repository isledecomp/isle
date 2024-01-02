#include "mxdschunk.h"

DECOMP_SIZE_ASSERT(MxDSChunk, 0x1c);

// FUNCTION: LEGO1 0x100be050
MxDSChunk::MxDSChunk()
{
	m_flags = 0;
	m_data = NULL;
	m_objectId = -1;
	m_time = 0;
	m_length = 0;
}

// FUNCTION: LEGO1 0x100be170
MxDSChunk::~MxDSChunk()
{
	if (m_flags & Flag_Bit1)
		delete[] m_data;
}

// FUNCTION: LEGO1 0x100be1e0
MxU32 MxDSChunk::ReturnE()
{
	return 0xe;
}
