#ifndef ACT2ACTOR_H
#define ACT2ACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6078 LegoPathActor
// VTABLE: LEGO1 0x100d6148 LegoAnimActor
// SIZE 0x1a8
class Act2Actor : public LegoAnimActor {
public:
	Act2Actor();

	void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2) override; // vtable+0x24
	void SetWorldSpeed(MxFloat p_worldSpeed) override;                    // vtable+0x30
	MxS32 VTable0x68(Vector3&, Vector3&, Vector3&) override;              // vtable+0x68
	void VTable0x70(float p_und) override;                                // vtable+0x70
	MxResult VTable0x94(LegoPathActor*, MxBool) override;                 // vtable+0x94
	MxResult VTable0x9c() override;                                       // vtable+0x9c
	MxS32 VTable0xa0() override;                                          // vtable+0xa0

	// SYNTHETIC: LEGO1 0x1001a0a0
	// Act2Actor::`scalar deleting destructor'

private:
	undefined m_unk0x1c[0x34]; // 0x1c
};

#endif // ACT2ACTOR_H
