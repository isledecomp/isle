#ifndef ACT2ACTOR_H
#define ACT2ACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6078 LegoPathActor
// VTABLE: LEGO1 0x100d6148 LegoAnimActor
// SIZE 0x1a8
class Act2Actor : public LegoAnimActor {
public:
	Act2Actor();

	void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2) override;   // vtable+0x24
	void SetWorldSpeed(MxFloat p_worldSpeed) override;                      // vtable+0x30
	MxS32 VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3) override; // vtable+0x68
	void VTable0x70(float p_und) override;                                  // vtable+0x70
	MxResult VTable0x94(LegoPathActor*, MxBool) override;                   // vtable+0x94
	MxResult VTable0x9c() override;                                         // vtable+0x9c
	MxS32 VTable0xa0() override;                                            // vtable+0xa0

	void FUN_10019520();

	// SYNTHETIC: LEGO1 0x1001a0a0
	// Act2Actor::`scalar deleting destructor'

private:
	undefined m_unk0x1c;  // 0x1c
	undefined m_unk0x1d;  // 0x1d
	undefined m_unk0x1e;  // 0x1e
	MxBool m_unk0x1f;     // 0x1f
	undefined4 m_unk0x20; // 0x20
	undefined4 m_unk0x24; // 0x24
	undefined4 m_unk0x28; // 0x28
	undefined4 m_unk0x2c; // 0x2c
	undefined4 m_unk0x30; // 0x30
	undefined4 m_unk0x34; // 0x34
	undefined4 m_unk0x38; // 0x38
	undefined4 m_unk0x3c; // 0x3c
	undefined m_unk0x40;  // 0x40
	undefined4 m_unk0x44; // 0x44
	undefined m_unk0x48;  // 0x48
	undefined4 m_unk0x4c; // 0x4c
};

#endif // ACT2ACTOR_H
