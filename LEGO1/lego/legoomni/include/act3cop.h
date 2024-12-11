#ifndef ACT3COP_H
#define ACT3COP_H

#include "act3.h"
#include "act3actors.h"

// VTABLE: LEGO1 0x100d7750 LegoPathActor
// VTABLE: LEGO1 0x100d7820 LegoAnimActor
// SIZE 0x188
class Act3Cop : public Act3Actor {
public:
	Act3Cop();

	void ParseAction(char* p_extra) override;             // vtable+0x20
	void VTable0x70(float p_time) override;               // vtable+0x70
	MxResult VTable0x94(LegoPathActor*, MxBool) override; // vtable+0x94
	MxResult VTable0x9c() override;                       // vtable+0x9c

	MxFloat GetUnknown0x20() { return m_unk0x20; }

	void SetUnknown0x20(MxFloat p_unk0x20) { m_unk0x20 = p_unk0x20; }

	void FUN_10040360();

	// SYNTHETIC: LEGO1 0x10043120
	// Act3Cop::`scalar deleting destructor'

private:
	MxFloat m_unk0x20;       // 0x20
	Act3* m_world;           // 0x24
	undefined4 m_unk0x24[2]; // 0x28
};

#endif // ACT3COP_H
