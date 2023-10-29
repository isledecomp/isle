#include "mxdsbuffer.h"

DECOMP_SIZE_ASSERT(MxDSBuffer, 0x34);

// OFFSET: LEGO1 0x100c6470
MxDSBuffer::MxDSBuffer()
{
	m_unk20 = 0;
	m_pBuffer = NULL;
	m_pIntoBuffer = NULL;
	m_pIntoBuffer2 = NULL;
	m_unk14 = 0;
	m_unk18 = 0;
	m_unk1c = 0;
	m_writeOffset = 0;
	m_bytesRemaining = 0;
	m_mode = 2;
	m_unk30 = 0;
}

// OFFSET: LEGO1 0x100c6530
MxDSBuffer::~MxDSBuffer()
{
	// TODO
}

// OFFSET: LEGO1 0x100c6780
MxResult MxDSBuffer::FUN_100c6780(void* p_buffer, MxU32 p_size)
{
	m_pBuffer = p_buffer;
	m_pIntoBuffer = p_buffer;
	m_pIntoBuffer2 = p_buffer;
	m_bytesRemaining = p_size;
	m_writeOffset = p_size;
	m_mode = 2;
	return SUCCESS;
}

// OFFSET: LEGO1 0x100c6f80
void MxDSBuffer::FUN_100c6f80(MxU32 p_unk)
{
	if (p_unk < m_writeOffset)
	{
		m_pIntoBuffer2 = p_unk + m_pIntoBuffer;
	}
}
