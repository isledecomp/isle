#ifndef ACT2GENACTOR_H
#define ACT2GENACTOR_H

#include "legopathactor.h"

// VTABLE: LEGO1 0x100d4ed8
// SIZE 0x154
class Act2GenActor : public LegoPathActor {
	MxResult HitActor(LegoPathActor* p_actor, MxBool) override; // vtable+0x94

	// SYNTHETIC: LEGO1 0x1000f5a0
	// Act2GenActor::`scalar deleting destructor'

private:
	static MxLong g_lastHitActorTime;
};

#endif // ACT2GENACTOR_H
