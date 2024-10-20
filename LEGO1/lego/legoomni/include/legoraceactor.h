#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"

class Matrix4;

// VTABLE: LEGO1 0x100d5b78 LegoAnimActor
// VTABLE: LEGO1 0x100d5b88 LegoPathActor
// VTABLE: LEGO1 0x100d5c54 LegoRaceActor
// VTABLE: BETA10 0x101be380 LegoAnimActor
// VTABLE: BETA10 0x101be398 LegoPathActor
// VTABLE: BETA10 0x101be488 LegoRaceActor
// SIZE 0x180
class LegoRaceActor : public virtual LegoAnimActor {
public:
	LegoRaceActor();

	// FUNCTION: LEGO1 0x10014b00
	// FUNCTION: BETA10 0x100aaae0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0bf4
		return "LegoRaceActor";
	}

	// FUNCTION: LEGO1 0x10014b20
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	MxS32 VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3) override; // vtable+0x68
	MxU32 VTable0x90(float p_float, Matrix4& p_matrix) override;            // vtable+0x90
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override;    // vtable+0x94

	// FUNCTION: LEGO1 0x10014aa0
	// FUNCTION: BETA10 0x100ca038
	virtual MxResult FUN_10014aa0() { return SUCCESS; }

	// SYNTHETIC: LEGO1 0x10012c10
	// LegoRaceActor::`vbase destructor'

	// SYNTHETIC: LEGO1 0x10014ac0
	// LegoRaceActor::`scalar deleting destructor'

private:
	MxFloat m_unk0x08; // 0x08

	static Mx3DPointFloat g_unk0x10102b08;
};

// GLOBAL: LEGO1 0x100d5b68
// LegoRaceActor::`vbtable'{for `LegoRaceActor'}

// GLOBAL: LEGO1 0x100d5b60
// LegoRaceActor::`vbtable'{for `LegoAnimActor'}

#endif // LEGORACEACTOR_H
