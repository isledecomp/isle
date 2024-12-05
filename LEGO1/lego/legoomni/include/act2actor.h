#ifndef ACT2ACTOR_H
#define ACT2ACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6078 LegoPathActor
// VTABLE: LEGO1 0x100d6148 LegoAnimActor
// VTABLE: BETA10 0x101b80c0 LegoPathActor
// VTABLE: BETA10 0x101b81b0 LegoAnimActor
// SIZE 0x1a8
class Act2Actor : public LegoAnimActor {
public:
	struct UnknownListStructure {
		MxFloat m_position[3];  // 0x00
		MxFloat m_direction[3]; // 0x0c
		const char* m_boundary; // 0x18
		undefined m_unk0x1c;    // 0x1c
	};

	Act2Actor();

	void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2) override;   // vtable+0x24
	void SetWorldSpeed(MxFloat p_worldSpeed) override;                      // vtable+0x30
	MxS32 VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3) override; // vtable+0x68
	void VTable0x70(float p_und) override;                                  // vtable+0x70
	MxResult VTable0x94(LegoPathActor*, MxBool) override;                   // vtable+0x94
	MxResult VTable0x9c() override;                                         // vtable+0x9c
	MxS32 VTable0xa0() override;                                            // vtable+0xa0

	void FUN_10018980();
	void FUN_10019520();
	void FUN_10019560();
	void FUN_100192a0(undefined4 p_param);

	// SYNTHETIC: LEGO1 0x1001a0a0
	// Act2Actor::`scalar deleting destructor'

	// GLOBAL: LEGO1 0x100d6070
	// GLOBAL: BETA10 0x101b80b0
	// `vbtable'

private:
	undefined m_unk0x1c;              // 0x1c
	MxS8 m_unk0x1d;                   // 0x1d
	undefined m_unk0x1e;              // 0x1e
	MxBool m_unk0x1f;                 // 0x1f
	undefined4 m_unk0x20;             // 0x20
	undefined4 m_unk0x24;             // 0x24
	MxS8 m_unk0x28;                   // 0x28
	undefined4 m_unk0x2c;             // 0x2c
	undefined4 m_unk0x30;             // 0x30
	LegoAnimActorStruct* m_shootAnim; // 0x34
	LegoCacheSound* m_unk0x38;        // 0x38
	undefined4 m_unk0x3c;             // 0x3c
	undefined m_unk0x40;              // 0x40
	undefined4 m_unk0x44;             // 0x44
	MxS8 m_unk0x48;                   // 0x48
	undefined4 m_unk0x4c;             // 0x4c
};

// TEMPLATE: LEGO1 0x100194f0
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >

#endif // ACT2ACTOR_H
