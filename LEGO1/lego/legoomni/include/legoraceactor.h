#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"
#include "realtime/matrix.h"

/*
	VTABLE: LEGO1 0x100d5b78 LegoAnimActor
	VTABLE: LEGO1 0x100d5b88 LegoPathActor
	VTABLE: LEGO1 0x100d5c54 LegoRaceActor
*/
// SIZE 0x180
class LegoRaceActor : public virtual LegoAnimActor {
public:
	LegoRaceActor();

	// FUNCTION: LEGO1 0x10014af0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0bf4
		return "LegoRaceActor";
	}

	// FUNCTION: LEGO1 0x10014b10
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	void ParseAction(char*) override;                  // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	void VTable0x68() override;                        // vtable+0x68
	void VTable0x70(float p_float) override;           // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;    // vtable+0x74
	MxS32 VTable0x90() override;                       // vtable+0x90
	MxS32 VTable0x94() override;                       // vtable+0x94

	// FUNCTION: LEGO1 0x10014aa0
	virtual MxResult FUN_10014aa0() { return SUCCESS; }

	// SYNTHETIC: LEGO1 0x10014ab0
	// LegoRaceActor::`scalar deleting destructor'

private:
	undefined4 m_unk0x08; // 0x08
};

#endif // LEGORACEACTOR_H
