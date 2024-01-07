#ifndef TOWTRACK_H
#define TOWTRACK_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d7ee0
// SIZE 0x180
class TowTrack : public IslePathActor {
public:
	TowTrack();

	// FUNCTION: LEGO1 0x1004c7c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03b8
		return "TowTrack";
	}

	// FUNCTION: LEGO1 0x1004c7d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, TowTrack::ClassName()) || IslePathActor::IsA(p_name);
	}

private:
	// TODO: TowTrack field types
	undefined m_unk0x154[4];
	MxS32 m_unk0x164;
	MxS16 m_unk0x168;
	MxS16 m_unk0x16a;
	MxS16 m_unk0x16c;
	MxS16 m_unk0x16e;
	MxS32 m_unk0x170;
	MxS32 m_unk0x174;
	MxFloat m_unk0x178;
	undefined4 m_unk0x17c;
};

#endif // TOWTRACK_H
