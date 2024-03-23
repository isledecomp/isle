#ifndef ACT3ACTOR_H
#define ACT3ACTOR_H

#include "legoanimactor.h"

/*
	VTABLE: LEGO1 0x100d7668 LegoPathActor
	VTABLE: LEGO1 0x100d7738 LegoAnimActor
*/
// SIZE 0x178
class Act3Actor : public LegoAnimActor {
public:
	Act3Actor();

	// FUNCTION: LEGO1 0x100433b0
	inline const char* ClassName() const override
	{
		// STRING: LEGO1 0x100f03ac
		return "Act3Actor";
	}

private:
	undefined4 m_unk0x1c; // 0x1c
};

#endif // ACT3ACTOR_H
