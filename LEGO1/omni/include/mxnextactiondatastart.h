#ifndef MXNEXTACTIONDATASTART_H
#define MXNEXTACTIONDATASTART_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc9a0
// VTABLE: BETA10 0x101c26a8
// SIZE 0x14
class MxNextActionDataStart : public MxCore {
public:
	// inlined constructor at 0x100c1847
	MxNextActionDataStart(MxU32 p_objectId, MxS16 p_unk0x24, MxU32 p_data)
	{
		m_objectId = p_objectId;
		m_unk0x24 = p_unk0x24;
		m_data = p_data;
	}

	// FUNCTION: LEGO1 0x100c1900
	// FUNCTION: BETA10 0x1014f660
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025a0
		return "MxNextActionDataStart";
	}

	// FUNCTION: LEGO1 0x100c1910
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxNextActionDataStart::ClassName()) || MxCore::IsA(p_name);
	}

	MxU32 GetObjectId() const { return m_objectId; }
	MxS16 GetUnknown24() const { return m_unk0x24; }
	MxU32 GetData() const { return m_data; }
	void SetData(MxU32 p_data) { m_data = p_data; }

	// SYNTHETIC: LEGO1 0x100c1990
	// MxNextActionDataStart::`scalar deleting destructor'

private:
	MxU32 m_objectId; // 0x08
	MxS16 m_unk0x24;  // 0x0c
	MxU32 m_data;     // 0x10
};

#endif // MXNEXTACTIONDATASTART_H
