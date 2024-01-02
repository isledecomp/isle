#ifndef MXDSCHUNK_H
#define MXDSCHUNK_H

#include "decomp.h"
#include "mxcore.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100dc7f8
// SIZE 0x1c
class MxDSChunk : public MxCore {
public:
	enum {
		Flag_Bit1 = 0x01,
		Flag_End = 0x02,
		Flag_Bit3 = 0x04,
		Flag_Split = 0x10,
		Flag_Bit16 = 0x8000
	};

	MxDSChunk();
	virtual ~MxDSChunk() override;

	// FUNCTION: LEGO1 0x100be0c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e6c
		return "MxDSChunk";
	}

	// FUNCTION: LEGO1 0x100be0d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSChunk::ClassName()) || MxCore::IsA(p_name);
	}

	static MxU32 ReturnE();

	inline void SetFlags(MxU16 p_flags) { m_flags = p_flags; }
	inline void SetObjectId(undefined4 p_objectid) { m_objectId = p_objectid; }
	inline void SetTime(MxLong p_time) { m_time = p_time; }
	inline void SetLength(MxU32 p_length) { m_length = p_length; }
	inline void SetData(MxU8* p_data) { m_data = p_data; }

	inline MxU16 GetFlags() { return m_flags; }
	inline undefined4 GetObjectId() { return m_objectId; }
	inline MxLong GetTime() { return m_time; }
	inline MxU32 GetLength() { return m_length; }
	inline MxU8* GetData() { return m_data; }

	inline void Release()
	{
		if (m_data)
			delete[] m_data;
	}

protected:
	MxU16 m_flags;    // 0x8
	MxU32 m_objectId; // 0xc
	MxLong m_time;    // 0x10
	MxU32 m_length;   // 0x14
	MxU8* m_data;     // 0x18
};

#endif // MXDSCHUNK_H
