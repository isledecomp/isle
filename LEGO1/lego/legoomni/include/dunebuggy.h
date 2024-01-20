#ifndef DUNEBUGGY_H
#define DUNEBUGGY_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d8f98
// SIZE 0x16c
class DuneBuggy : public IslePathActor {
public:
	DuneBuggy();

	// FUNCTION: LEGO1 0x10067c30
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0410
		return "DuneBuggy";
	}

	// FUNCTION: LEGO1 0x10067c40
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, DuneBuggy::ClassName()) || IslePathActor::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override;              // vtable+0x18
	virtual void VTable0x70(float p_float) override;                       // vtable+0x70
	virtual MxU32 VTable0xcc() override;                                   // vtable+0xcc
	virtual MxU32 VTable0xd4(MxType17NotificationParam& p_param) override; // vtable+0xd4
	virtual MxU32 VTable0xdc(MxType19NotificationParam& p_param) override; // vtable+0xdc
	virtual void VTable0xe4() override;                                    // vtable+0xe4

	// SYNTHETIC: LEGO1 0x10067dc0
	// DuneBuggy::`scalar deleting destructor'

private:
	// TODO: Double check DuneBuggy field types
	undefined4 m_unk0x160;
	MxFloat m_unk0x164;
	undefined4 m_unk0x168;
};

#endif // DUNEBUGGY_H
