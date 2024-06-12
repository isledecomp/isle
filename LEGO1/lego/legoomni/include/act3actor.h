#ifndef ACT3ACTOR_H
#define ACT3ACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d7668 LegoPathActor
// VTABLE: LEGO1 0x100d7738 LegoAnimActor
// SIZE 0x178
class Act3Actor : public LegoAnimActor {
public:
	Act3Actor();

	// FUNCTION: LEGO1 0x100431b0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03ac
		return "Act3Actor";
	}

	MxU32 VTable0x90(float, Matrix4&) override;           // vtable+0x90
	MxResult VTable0x94(LegoPathActor*, MxBool) override; // vtable+0x94

	// SYNTHETIC: LEGO1 0x10043330
	// Act3Actor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10040fa0
	// Act3Actor::~Act3Actor

private:
	undefined4 m_unk0x1c; // 0x1c
};

#endif // ACT3ACTOR_H
