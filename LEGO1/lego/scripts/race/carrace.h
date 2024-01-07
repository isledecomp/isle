#ifndef CARRACE_H
#define CARRACE_H

#include "decomp.h"
#include "legorace.h"

// VTABLE: LEGO1 0x100d5e50
// SIZE 0x154
class CarRace : public LegoRace {
public:
	CarRace();

	// FUNCTION: LEGO1 0x10016b20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0528
		return "CarRace";
	}

	// FUNCTION: LEGO1 0x10016b30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRace::ClassName()) || LegoRace::IsA(p_name);
	}

private:
	undefined m_unk0x144[12]; // 0x144
	undefined4 m_unk0x150;    // 0x150
};

#endif // CARRACE_H
