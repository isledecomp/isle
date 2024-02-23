#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"
#include "realtime/matrix.h"

// VTABLE: LEGO1 0x100d5b88
class LegoRaceActor : public LegoAnimActor {
public:
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

	// SYNTHETIC: LEGO1 0x10014ab0
	// LegoRaceActor::`scalar deleting destructor'
};

#endif // LEGORACEACTOR_H
