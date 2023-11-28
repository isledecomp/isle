#ifndef CARRACESTATE_H
#define CARRACESTATE_H

#include "racestate.h"

// VTABLE: LEGO1 0x100d4b70
// SIZE 0x2c
class CarRaceState : public RaceState {
public:
	// FUNCTION: LEGO1 0x1000dd30
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f009c
		return "CarRaceState";
	}

	// FUNCTION: LEGO1 0x1000dd40
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, CarRaceState::ClassName()) || RaceState::IsA(name);
	}
};

#endif // CARRACESTATE_H
