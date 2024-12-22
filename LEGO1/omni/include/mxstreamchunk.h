#ifndef MXSTREAMCHUNK_H
#define MXSTREAMCHUNK_H

#include "mxdschunk.h"

class MxDSBuffer;
class MxStreamListMxDSSubscriber;

// VTABLE: LEGO1 0x100dc2a8
// VTABLE: BETA10 0x101c1d20
// SIZE 0x20
class MxStreamChunk : public MxDSChunk {
public:
	// FUNCTION: BETA10 0x10134420
	MxStreamChunk() : m_buffer(NULL) {}

	~MxStreamChunk() override;

	// FUNCTION: LEGO1 0x100b1fe0
	// FUNCTION: BETA10 0x101344a0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e5c
		return "MxStreamChunk";
	}

	// FUNCTION: LEGO1 0x100b1ff0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamChunk::ClassName()) || MxDSChunk::IsA(p_name);
	}

	MxDSBuffer* GetBuffer() { return m_buffer; }

	MxResult ReadChunk(MxDSBuffer* p_buffer, MxU8* p_chunkData);
	MxU32 ReadChunkHeader(MxU8* p_chunkData);
	MxResult SendChunk(MxStreamListMxDSSubscriber& p_subscriberList, MxBool p_append, MxS16 p_obj24val);
	void SetBuffer(MxDSBuffer* p_buffer);

	static MxU16* IntoFlags(MxU8* p_buffer);
	static MxU32* IntoObjectId(MxU8* p_buffer);
	static MxLong* IntoTime(MxU8* p_buffer);
	static MxU32* IntoLength(MxU8* p_buffer);

private:
	MxDSBuffer* m_buffer; // 0x1c
};

// SYNTHETIC: LEGO1 0x100b20a0
// MxStreamChunk::`scalar deleting destructor'

#endif // MXSTREAMCHUNK_H
