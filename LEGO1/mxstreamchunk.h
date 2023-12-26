#ifndef MXSTREAMCHUNK_H
#define MXSTREAMCHUNK_H

#include "mxdschunk.h"
#include "mxdsobject.h"

class MxDSBuffer;
class MxStreamListMxDSSubscriber;

// VTABLE: LEGO1 0x100dc2a8
// SIZE 0x20
class MxStreamChunk : public MxDSChunk {
public:
	inline MxStreamChunk() : m_buffer(NULL) {}
	virtual ~MxStreamChunk() override;

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

	inline MxDSBuffer* GetBuffer() { return m_buffer; }

	MxResult ReadChunk(MxDSBuffer* p_buffer, MxU8* p_chunkData);
	MxU32 ReadChunkHeader(MxU8* p_chunkData);
	MxResult SendChunk(MxStreamListMxDSSubscriber& p_subscriberList, MxBool p_append, MxS16 p_obj24val);
	void SetBuffer(MxDSBuffer* p_buffer);

	static MxU16* IntoFlags(MxU8* p_buffer);
	static MxU32* IntoPlus0x12(MxU8* p_buffer);
	static MxU32* IntoPlus0xa(MxU8* p_buffer);
	static MxU32* IntoPlus0xe(MxU8* p_buffer);

private:
	MxDSBuffer* m_buffer; // 0x1c
};

// SYNTHETIC: LEGO1 0x100b20a0
// MxStreamChunk::`scalar deleting destructor'

#endif // MXSTREAMCHUNK_H
