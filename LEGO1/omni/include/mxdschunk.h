#ifndef MXDSCHUNK_H
#define MXDSCHUNK_H

#include "decomp.h"
#include "mxcore.h"
#include "mxtypes.h"

#define DS_CHUNK_BIT1 0x01
#define DS_CHUNK_END_OF_STREAM 0x02
#define DS_CHUNK_BIT3 0x04
#define DS_CHUNK_SPLIT 0x10
#define DS_CHUNK_BIT16 0x8000

// VTABLE: LEGO1 0x100dc7f8
// VTABLE: BETA10 0x101c23d0
// SIZE 0x1c
class MxDSChunk : public MxCore {
public:
	MxDSChunk();
	~MxDSChunk() override;

	// FUNCTION: LEGO1 0x100be0c0
	// FUNCTION: BETA10 0x10134580
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e6c
		return "MxDSChunk";
	}

	// FUNCTION: LEGO1 0x100be0d0
	// FUNCTION: BETA10 0x10134520
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSChunk::ClassName()) || MxCore::IsA(p_name);
	}

	static MxU32 GetHeaderSize();
	static MxU32* IntoType(MxU8* p_buffer) { return (MxU32*) p_buffer; }
	static MxU32* IntoLength(MxU8* p_buffer) { return (MxU32*) (p_buffer + 4); }
	static MxU32 Size(MxU32 p_dataSize) { return (p_dataSize & 1) + p_dataSize + 8; }
	static MxU8* End(MxU8* p_buffer) { return p_buffer + Size(*IntoLength(p_buffer)); }

	void SetChunkFlags(MxU16 p_flags) { m_flags = p_flags; }
	void SetObjectId(undefined4 p_objectid) { m_objectId = p_objectid; }

	// FUNCTION: BETA10 0x101343f0
	void SetTime(MxLong p_time) { m_time = p_time; }

	void SetLength(MxU32 p_length) { m_length = p_length; }
	void SetData(MxU8* p_data) { m_data = p_data; }

	// FUNCTION: BETA10 0x1005ab90
	MxU16 GetChunkFlags() { return m_flags; }

	// FUNCTION: BETA10 0x10159110
	undefined4 GetObjectId() { return m_objectId; }

	// FUNCTION: BETA10 0x1005ab30
	MxLong GetTime() { return m_time; }

	// FUNCTION: BETA10 0x1008d000
	MxU32 GetLength() { return m_length; }

	// FUNCTION: BETA10 0x10056d60
	MxU8* GetData() { return m_data; }

	void Release()
	{
		if (m_data) {
			delete[] m_data;
		}
	}

	// SYNTHETIC: LEGO1 0x100be150
	// SYNTHETIC: BETA10 0x101474c0
	// MxDSChunk::`scalar deleting destructor'

protected:
	MxU16 m_flags;    // 0x08
	MxU32 m_objectId; // 0x0c
	MxLong m_time;    // 0x10
	MxU32 m_length;   // 0x14
	MxU8* m_data;     // 0x18
};

#endif // MXDSCHUNK_H
