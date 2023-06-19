#ifndef GASSTATIONSTATE_H
#define GASSTATIONSTATE_H

#include "legostate.h"

class GasStationState : public LegoState
{
	// OFFSET LEGO1 0x10005eb0
	GasStationState();

	// field 0x8 is prob MxResult
	// field 0xc is prob MxResult
	// field 0x10 is prob MxResult
};

#endif // GASSTATIONSTATE_H