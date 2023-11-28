#ifndef MXSTREAMCHUNK_H
#define MXSTREAMCHUNK_H

#include "mxdschunk.h"

// VTABLE: LEGO1 0x100dc2a8
// SIZE 0x20
class MxStreamChunk : public MxDSChunk {
public:
	inline MxStreamChunk() : m_unk1c(NULL) {}

	// FUNCTION: LEGO1 0x100b1fe0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x10101e5c
		return "MxStreamChunk";
	}

	// FUNCTION: LEGO1 0x100b1ff0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxStreamChunk::ClassName()) || MxDSChunk::IsA(name);
	}

private:
	void* m_unk1c; // 0x1c
};

#endif // MXSTREAMCHUNK_H
