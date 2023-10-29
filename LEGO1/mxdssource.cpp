#include "mxdssource.h"

#include "mxdsbuffer.h"

// OFFSET: LEGO1 0x100bffd0
void MxDSSource::ReadToBuffer(MxDSBuffer* p_buffer)
{
	Read((unsigned char*) p_buffer->GetBuffer(), p_buffer->GetWriteOffset());
}

// OFFSET: LEGO1 0x100bfff0
MxLong MxDSSource::GetLengthInDWords()
{
	return m_lengthInDWords;
}

// OFFSET: LEGO1 0x100c0000
MxU32* MxDSSource::GetBuffer()
{
	return m_pBuffer;
}
