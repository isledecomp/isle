#ifndef MXNEXTACTIONDATASTART_H
#define MXNEXTACTIONDATASTART_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc9a0
// SIZE 0x14
class MxNextActionDataStart : public MxCore {
public:
	// inlined constructor at 0x100c1847
	inline MxNextActionDataStart(MxU32 p_objectId, MxS16 p_unk0x24, MxU32 p_data)
	{
		m_objectId = p_objectId;
		m_unk0x24 = p_unk0x24;
		m_data = p_data;
	}

	// FUNCTION: LEGO1 0x100c1900
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x101025a0
		return "MxNextActionDataStart";
	}

	// FUNCTION: LEGO1 0x100c1910
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxNextActionDataStart::ClassName()) || MxCore::IsA(p_name);
	}

	inline MxU32 GetObjectId() const { return m_objectId; }
	inline MxS16 GetUnknown24() const { return m_unk0x24; }
	inline MxU32 GetData() const { return m_data; }
	inline void SetData(MxU32 p_data) { m_data = p_data; }

private:
	MxU32 m_objectId; // 0x08
	MxS16 m_unk0x24;  // 0x0c
	MxU32 m_data;     // 0x10
};

#endif // MXNEXTACTIONDATASTART_H
