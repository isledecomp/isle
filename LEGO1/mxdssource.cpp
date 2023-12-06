#include "mxdssource.h"

#include "mxdsbuffer.h"

// FUNCTION: LEGO1 0x100bffd0
void MxDSSource::ReadToBuffer(MxDSBuffer* p_buffer)
{
	Read(p_buffer->GetBuffer(), p_buffer->GetWriteOffset());
}

// FUNCTION: LEGO1 0x100bfff0
MxLong MxDSSource::GetLengthInDWords()
{
	return m_lengthInDWords;
}

// FUNCTION: LEGO1 0x100c0000
MxU32* MxDSSource::GetBuffer()
{
	return m_pBuffer;
}
