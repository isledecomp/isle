#ifndef LEGORACECAR_H
#define LEGORACECAR_H

#include "legocarraceactor.h"
#include "legopathactor.h"
#include "legoracemap.h"

/*
	VTABLE: LEGO1 0x100d58a0 LegoRaceActor
	VTABLE: LEGO1 0x100d58a8 LegoAnimActor
	VTABLE: LEGO1 0x100d58b8 LegoPathActor
	VTABLE: LEGO1 0x100d5894 LegoRaceMap
	VTABLE: LEGO1 0x100d5898 LegoCarRaceActor
*/
// SIZE 0x200
class LegoRaceCar : public LegoCarRaceActor, public LegoRaceMap {
public:
	LegoRaceCar();
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10014290
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0548
		return "LegoRaceCar";
	}

	// FUNCTION: LEGO1 0x100142b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}

	void ParseAction(char*) override;                                    // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override;                   // vtable+0x30
	void VTable0x6c() override;                                          // vtable+0x6c
	void VTable0x70(float p_float) override;                             // vtable+0x70
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void VTable0x98() override;                                          // vtable+0x98
	MxResult WaitForAnimation() override;                                // vtable+0x9c

	virtual void FUN_10012ea0(float p_worldSpeed);
	virtual void FUN_10012ff0(float);
	virtual MxBool FUN_10013130(float);

	// SYNTHETIC: LEGO1 0x10014230
	// LegoRaceCar::`scalar deleting destructor'

private:
	undefined m_unk0x54;      // 0x54
	undefined4 m_unk0x58;     // 0x58
	Mx3DPointFloat m_unk0x5c; // 0x5c
	undefined4 m_unk0x70;     // 0x70
	undefined4 m_unk0x74;     // 0x74
	undefined4 m_unk0x78;     // 0x78
	undefined4 m_unk0x7c;     // 0x7c
};

#endif // LEGORACECAR_H
