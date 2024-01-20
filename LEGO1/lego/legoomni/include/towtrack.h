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

	virtual MxLong Notify(MxParam& p_param) override;                      // vtable+0x04
	virtual MxResult Create(MxDSAction& p_dsAction) override;              // vtable+0x18
	virtual void VTable0x70(float p_float) override;                       // vtable+0x70
	virtual MxU32 VTable0xcc() override;                                   // vtable+0xcc
	virtual MxU32 VTable0xd4(MxType17NotificationParam& p_param) override; // vtable+0xd4
	virtual MxU32 VTable0xd8(MxType18NotificationParam& p_param) override; // vtable+0xd8
	virtual MxU32 VTable0xdc(MxType19NotificationParam& p_param) override; // vtable+0xdc
	virtual void VTable0xe4() override;                                    // vtable+0xe4

	// SYNTHETIC: LEGO1 0x1004c950
	// TowTrack::`scalar deleting destructor'

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
