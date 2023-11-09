#ifndef MXDSCHUNK_H
#define MXDSCHUNK_H

#include "decomp.h"
#include "mxcore.h"
#include "mxtypes.h"

// VTABLE 0x100dc7f8
// SIZE 0x1c
class MxDSChunk : public MxCore {
public:
	enum {
		Flag_Bit1 = 0x01,
		Flag_Bit2 = 0x02,
		Flag_Bit3 = 0x04,
	};

	MxDSChunk();
	virtual ~MxDSChunk() override;

	// OFFSET: LEGO1 0x100be0c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x10101e6c
		return "MxDSChunk";
	}

	// OFFSET: LEGO1 0x100be0d0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSChunk::ClassName()) || MxCore::IsA(name);
	}

	inline MxU16 GetFlags() { return m_flags; }
	inline MxLong GetTime() { return m_time; }

	inline void ReleaseUnk18()
	{
		if (m_unk18)
			delete[] m_unk18;
	}

private:
	MxU16 m_flags;      // 0x8
	undefined4 m_unk0c; // 0xc
	MxLong m_time;      // 0x10
	undefined4 m_unk14; // 0x14
	MxU8* m_unk18;      // 0x18
};

#endif // MXDSCHUNK_H
