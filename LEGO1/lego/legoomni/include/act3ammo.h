#ifndef ACT3AMMO_H
#define ACT3AMMO_H

#include "legopathactor.h"
#include "mxgeometry/mxgeometry3d.h"

// VTABLE: LEGO1 0x100d8460
// SIZE 0x1a0
class Act3Ammo : public LegoPathActor {
public:
	Act3Ammo();
	~Act3Ammo() override;

	void Destroy(MxBool p_fromDestructor) override; // vtable+0x1c
	void VTable0x70(float p_time) override;         // vtable+0x70

	// SYNTHETIC: LEGO1 0x10053880
	// Act3Ammo::`scalar deleting destructor'

private:
	undefined2 m_unk0x154;        // 0x154
	undefined4 m_unk0x158;        // 0x158
	undefined4 m_unk0x15c;        // 0x15c
	Mx3DPointFloat m_unk0x160[3]; // 0x160
	undefined4 m_unk0x19c;        // 0x19c
};

#endif // ACT3AMMO_H
