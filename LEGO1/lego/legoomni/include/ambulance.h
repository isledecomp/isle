#ifndef AMBULANCE_H
#define AMBULANCE_H

#include "islepathactor.h"

// VTABLE: LEGO1 0x100d71a8
// SIZE 0x184
class Ambulance : public IslePathActor {
public:
	Ambulance();

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10035fa0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03c4
		return "Ambulance";
	}

	// FUNCTION: LEGO1 0x10035fb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Ambulance::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;            // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;              // vtable+0x1c
	void VTable0x70(float p_float) override;                     // vtable+0x70
	MxU32 VTable0xcc() override;                                 // vtable+0xcc
	MxU32 VTable0xd4(LegoControlManagerEvent& p_param) override; // vtable+0xd4
	MxU32 VTable0xdc(MxType19NotificationParam&) override;       // vtable+0xdc
	void VTable0xe4() override;                                  // vtable+0xe4

	void FUN_10036e60();
	void FUN_10037060();

	// SYNTHETIC: LEGO1 0x10036130
	// Ambulance::`scalar deleting destructor'

private:
	// TODO: Ambulance fields
	undefined m_unk0x160[4];
	MxS32 m_unk0x164;
	MxS16 m_unk0x168;
	MxS16 m_unk0x16a;
	MxS16 m_unk0x16c;
	MxS16 m_unk0x16e;
	MxS16 m_unk0x170;
	MxS16 m_unk0x172;
	MxS32 m_unk0x174;
	MxS32 m_unk0x178;
	MxFloat m_unk0x17c;
	undefined m_unk0x180[4];
};

#endif // AMBULANCE_H
