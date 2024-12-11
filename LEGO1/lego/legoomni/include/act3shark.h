#ifndef ACT3SHARK_H
#define ACT3SHARK_H

#include "legoanimactor.h"

class Act3;
class Act3Ammo;

// VTABLE: LEGO1 0x100d7920 LegoPathActor
// VTABLE: LEGO1 0x100d79f0 LegoAnimActor
// SIZE 0x1a8
class Act3Shark : public LegoAnimActor {
public:
	Act3Shark();

	// FUNCTION: LEGO1 0x100430d0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03a0
		return "Act3Shark";
	}

	void ParseAction(char*) override;       // vtable+0x20
	void VTable0x70(float p_time) override; // vtable+0x70

	// LegoAnimActor vtable
	virtual MxResult FUN_10042ce0(Act3Ammo* p_ammo); // vtable+0x10

	MxFloat GetUnknown0x2c() { return m_unk0x2c; }

	void SetUnknown0x2c(MxFloat p_unk0x2c) { m_unk0x2c = p_unk0x2c; }

	// SYNTHETIC: LEGO1 0x10043030
	// Act3Shark::`scalar deleting destructor'

private:
	list<Act3Ammo*> m_unk0x1c;      // 0x1c
	undefined4 m_unk0x28;           // 0x28
	MxFloat m_unk0x2c;              // 0x2c
	Act3* m_a3;                     // 0x30
	LegoAnimActorStruct* m_unk0x34; // 0x34
	LegoROI* m_unk0x38;             // 0x38
	Mx3DPointFloat m_unk0x3c;       // 0x3c
};

// TEMPLATE: LEGO1 0x10042c20
// list<Act3Ammo *,allocator<Act3Ammo *> >::~list<Act3Ammo *,allocator<Act3Ammo *> >

// TEMPLATE: LEGO1 0x10042c90
// List<Act3Ammo *>::~List<Act3Ammo *>

// GLOBAL: LEGO1 0x100d7918
// Act3Shark::`vbtable'

#endif // ACT3SHARK_H
