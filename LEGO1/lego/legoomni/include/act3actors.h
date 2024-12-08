#ifndef ACT3ACTORS_H
#define ACT3ACTORS_H

#include "legoanimactor.h"

// File name verified by multiple assertions, e.g. BETA10 0x10018391

// VTABLE: LEGO1 0x100d7668 LegoPathActor
// VTABLE: LEGO1 0x100d7738 LegoAnimActor
// VTABLE: BETA10 0x101b8a98 LegoPathActor
// SIZE 0x178
class Act3Actor : public LegoAnimActor {
public:
	Act3Actor();

	// FUNCTION: LEGO1 0x100431b0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03ac
		return "Act3Actor";
	}

	MxU32 VTable0x90(float p_time, Matrix4& p_transform) override;       // vtable+0x90
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94

	// SYNTHETIC: LEGO1 0x10043330
	// Act3Actor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10040fa0
	// Act3Actor::~Act3Actor

private:
	MxFloat m_unk0x1c; // 0x1c

	static Mx3DPointFloat g_unk0x10104ef0;
};

// GLOBAL: LEGO1 0x100d7660
// Act3Actor::`vbtable'

#endif // ACT3ACTORS_H
