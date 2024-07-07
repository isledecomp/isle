#ifndef ACT3BRICKSTER_H
#define ACT3BRICKSTER_H

#include "act3actors.h"

// VTABLE: LEGO1 0x100d7838 LegoPathActor
// VTABLE: LEGO1 0x100d7908 LegoAnimActor
// SIZE 0x1b4
class Act3Brickster : public Act3Actor {
public:
	Act3Brickster();
	~Act3Brickster() override;

	void ParseAction(char* p_extra) override;             // vtable+0x20
	void VTable0x70(float p_und) override;                // vtable+0x70
	MxResult VTable0x94(LegoPathActor*, MxBool) override; // vtable+0x94
	void SwitchBoundary(
		LegoPathBoundary*& p_boundary,
		LegoUnknown100db7f4*& p_edge,
		float& p_unk0xe4
	) override;                     // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	// SYNTHETIC: LEGO1 0x10043250
	// Act3Brickster::`scalar deleting destructor'

private:
	undefined4 m_unk0x20[15]; // 0x20
};

#endif // ACT3BRICKSTER_H
