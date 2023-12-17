#ifndef MXSTREAMCHUNK_H
#define MXSTREAMCHUNK_H

#include "mxdschunk.h"

class MxDSBuffer;

// VTABLE: LEGO1 0x100dc2a8
// SIZE 0x20
class MxStreamChunk : public MxDSChunk {
public:
	inline MxStreamChunk() : m_unk0x1c(NULL) {}

	// FUNCTION: LEGO1 0x100b1fe0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x10101e5c
		return "MxStreamChunk";
	}

	// FUNCTION: LEGO1 0x100b1ff0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamChunk::ClassName()) || MxDSChunk::IsA(p_name);
	}

	MxResult ReadChunk(MxDSBuffer* p_buffer, MxU8* p_chunkData);

private:
	void* m_unk0x1c; // 0x1c
};

#endif // MXSTREAMCHUNK_H
