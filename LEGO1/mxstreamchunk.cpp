#include "mxstreamchunk.h"

#include "mxdsbuffer.h"

// FUNCTION: LEGO1 0x100c2fe0
MxStreamChunk::~MxStreamChunk()
{
	if (m_buffer) {
		m_buffer->ReleaseRef(this);
	}
}

// FUNCTION: LEGO1 0x100c3050
MxResult MxStreamChunk::ReadChunk(MxDSBuffer* p_buffer, MxU8* p_chunkData)
{
	MxResult result = FAILURE;

	if (p_chunkData != NULL && *(MxU32*) p_chunkData == FOURCC('M', 'x', 'C', 'h')) {
		if (ReadChunkHeader(p_chunkData + 8)) {
			if (p_buffer) {
				SetBuffer(p_buffer);
				p_buffer->AddRef(this);
			}
			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c30a0
MxU32 MxStreamChunk::ReadChunkHeader(MxU8* p_chunkData)
{
	MxU32 headersize = 0;
	if(p_chunkData)
	{
		SetFlags(*(MxU16*)p_chunkData);
		SetObjectId(*(MxU32*)(p_chunkData + 2));
		SetTime(*(MxLong*)(p_chunkData + 6));
		SetLength(*(MxU32*)(p_chunkData + 10));
		SetData(p_chunkData + 14);
		headersize = (MxU32)(p_chunkData + 14) - (MxU32)p_chunkData;
	}
	return headersize;
}

// FUNCTION: LEGO1 0x100c3170
void MxStreamChunk::SetBuffer(MxDSBuffer* p_buffer)
{
	m_buffer = p_buffer;
}
