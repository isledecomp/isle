#ifndef MXSTREAMCHUNK_H
#define MXSTREAMCHUNK_H

#include "mxdschunk.h"

// VTABLE 0x100dc2a8
class MxStreamChunk : public MxDSChunk {
	// OFFSET: LEGO1 0x100b1fe0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x10101e5c
		return "MxStreamChunk";
	}

	// OFFSET: LEGO1 0x100b1ff0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxStreamChunk::ClassName()) || MxDSChunk::IsA(name);
	}
};

#endif // MXSTREAMCHUNK_H
