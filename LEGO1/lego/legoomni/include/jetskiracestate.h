#ifndef JETSKIRACESTATE_H
#define JETSKIRACESTATE_H

#include "racestate.h"

// VTABLE: LEGO1 0x100d4fa8
// SIZE 0x2c
class JetskiRaceState : public RaceState {
public:
	// FUNCTION: LEGO1 0x1000dc40
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00ac
		return "JetskiRaceState";
	}

	// FUNCTION: LEGO1 0x1000dc50
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JetskiRaceState::ClassName()) || RaceState::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f680
	// JetskiRaceState::`scalar deleting destructor'
};

#endif // JETSKIRACESTATE_H
