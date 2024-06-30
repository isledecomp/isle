#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"

class Matrix4;

// VTABLE: LEGO1 0x100d5b78 LegoAnimActor
// VTABLE: LEGO1 0x100d5b88 LegoPathActor
// VTABLE: LEGO1 0x100d5c54 LegoRaceActor
// SIZE 0x180
class LegoRaceActor : public virtual LegoAnimActor {
public:
	LegoRaceActor();

	// FUNCTION: LEGO1 0x10014b00
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0bf4
		return "LegoRaceActor";
	}

	// FUNCTION: LEGO1 0x10014b20
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	MxS32 VTable0x68(Vector3&, Vector3&, Vector3&) override;             // vtable+0x68
	MxU32 VTable0x90(float, Matrix4&) override;                          // vtable+0x90
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94

	// FUNCTION: LEGO1 0x10014aa0
	virtual MxResult FUN_10014aa0() { return SUCCESS; }

	// SYNTHETIC: LEGO1 0x10014ac0
	// LegoRaceActor::`scalar deleting destructor'

protected:
	undefined4 m_unk0x08; // 0x08
};

#endif // LEGORACEACTOR_H
