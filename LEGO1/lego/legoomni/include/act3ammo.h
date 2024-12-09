#ifndef ACT3AMMO_H
#define ACT3AMMO_H

#include "legopathactor.h"
#include "mxgeometry/mxgeometry3d.h"

class Act3;

// VTABLE: LEGO1 0x100d8460
// SIZE 0x1a0
class Act3Ammo : public LegoPathActor {
public:
	enum {
		c_placed = 0x04
	};

	Act3Ammo();
	~Act3Ammo() override;

	void Destroy(MxBool p_fromDestructor) override; // vtable+0x1c
	void VTable0x70(float p_time) override;         // vtable+0x70

	// FUNCTION: BETA10 0x10017750
	MxU32 IsPlaced() { return m_ammoFlag & c_placed; }

	MxFloat GetUnknown0x158() { return m_unk0x158; }

	// FUNCTION: BETA10 0x100177b0
	Mx3DPointFloat* GetUnknown0x160() { return m_unk0x160; }

	// FUNCTION: BETA10 0x100177e0
	MxFloat* GetUnknown0x19c() { return &m_unk0x19c; }

	void SetUnknown0x158(MxFloat p_unk0x158) { m_unk0x158 = p_unk0x158; }

	MxResult FUN_10053980(Act3* p_a3, MxU32 p_isDonut, MxS32 p_index);
	MxResult FUN_10053b40(Vector3& p_srcLoc, Vector3& p_srcDir, Vector3& p_srcUp);
	MxResult FUN_10053cb0(LegoPathController* p_controller, LegoPathBoundary* p_boundary, MxFloat p_unk0x19c);
	MxResult FUN_10053d30(LegoPathController* p_controller, MxFloat p_unk0x19c);

	// SYNTHETIC: LEGO1 0x10053880
	// Act3Ammo::`scalar deleting destructor'

private:
	MxU16 m_ammoFlag;             // 0x154
	MxFloat m_unk0x158;           // 0x158
	Act3* m_a3;                   // 0x15c
	Mx3DPointFloat m_unk0x160[3]; // 0x160
	MxFloat m_unk0x19c;           // 0x19c
};

#endif // ACT3AMMO_H
