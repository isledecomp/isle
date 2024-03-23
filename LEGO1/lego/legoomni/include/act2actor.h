#ifndef ACT2ACTOR_H
#define ACT2ACTOR_H

#include "legoanimactor.h"

/*
	VTABLE: LEGO1 0x100d6078 LegoPathActor
	VTABLE: LEGO1 0x100d6148 LegoAnimActor
*/
// SIZE 0x1a8
class Act2Actor : public LegoAnimActor {
public:
	Act2Actor();

	// SYNTHETIC: LEGO1 0x1001a090
	// Act2Actor::`scalar deleting destructor'

private:
	undefined m_unk0x1c[0x34]; // 0x1c
};

#endif // ACT2ACTOR_H
