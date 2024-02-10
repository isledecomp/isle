#ifndef JETSKIRACE_H
#define JETSKIRACE_H

#include "legorace.h"

// VTABLE: LEGO1 0x100d4fe8
// SIZE 0x144
class JetskiRace : public LegoRace {
public:
	// FUNCTION: LEGO1 0x1000daf0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0530
		return "JetskiRace";
	}

	// FUNCTION: LEGO1 0x1000db00
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JetskiRace::ClassName()) || LegoRace::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x64() override;                     // vtable+0x64
	undefined4 VTable0x6c(undefined4) override;       // vtable+0x6c
	undefined4 VTable0x70(undefined4) override;       // vtable+0x70
	undefined4 VTable0x74(undefined4) override;       // vtable+0x74
};

// SYNTHETIC: LEGO1 0x1000f530
// JetskiRace::`scalar deleting destructor'

#endif // JETSKIRACE_H
