#ifndef LEGOCARRACEACTOR_H
#define LEGOCARRACEACTOR_H

#include "legoraceactor.h"

/*
	VTABLE: LEGO1 0x100da0c0 LegoRaceActor
	VTABLE: LEGO1 0x100da0c8 LegoAnimActor
	VTABLE: LEGO1 0x100da0d8 LegoPathActor
	VTABLE: LEGO1 0x100da1a8 LegoCarRaceActor
*/
// SIZE 0x1a0
class LegoCarRaceActor : public virtual LegoRaceActor {
public:
	LegoCarRaceActor();

	// FUNCTION: LEGO1 0x10081650
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0568
		return "LegoCarRaceActor";
	}

	// FUNCTION: LEGO1 0x10081670
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarRaceActor::ClassName()) || LegoRaceActor::IsA(p_name);
	}

	void VTable0x6c() override;                                          // vtable+0x6c
	void VTable0x70(float p_float) override;                             // vtable+0x70
	MxU32 VTable0x90(float, Matrix4&) override;                          // vtable+0x90
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void VTable0x98() override;                                          // vtable+0x98
	MxResult WaitForAnimation() override;                                // vtable+0x9c

	virtual void FUN_10080590();

	// FUNCTION: LEGO1 0x10012bb0
	virtual void FUN_10012bb0(float p_unk0x14) { m_unk0x14 = p_unk0x14; }

	// FUNCTION: LEGO1 0x10012bc0
	virtual float FUN_10012bc0() { return m_unk0x14; }

	// FUNCTION: LEGO1 0x10012bd0
	virtual void FUN_10012bd0(float p_unk0x10) { m_unk0x10 = p_unk0x10; }

	// FUNCTION: LEGO1 0x10012be0
	virtual float FUN_10012be0() { return m_unk0x10; }

	// FUNCTION: LEGO1 0x10012bf0
	virtual void FUN_10012bf0(float p_unk0x18) { m_unk0x18 = p_unk0x18; }

	// FUNCTION: LEGO1 0x10012c00
	virtual float FUN_10012c00() { return m_unk0x18; }

	virtual void VTable0x1c(); // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10081610
	// LegoCarRaceActor::`scalar deleting destructor'

protected:
	float m_unk0x08;      // 0x08
	MxU8 m_unk0x0c;       // 0x0c
	float m_unk0x10;      // 0x10
	float m_unk0x14;      // 0x14
	float m_unk0x18;      // 0x18
	undefined4 m_unk0x1c; // 0x1c
};

#endif // LEGOCARRACEACTOR_H
