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
		c_pizza = 0x01,
		c_donut = 0x02,
		c_valid = 0x04,
		c_bit4 = 0x08,
		c_bit5 = 0x10
	};

	Act3Ammo();
	~Act3Ammo() override;

	void Destroy(MxBool p_fromDestructor) override; // vtable+0x1c
	void Animate(float p_time) override;            // vtable+0x70

	// FUNCTION: BETA10 0x10017750
	MxU32 IsValid() { return m_ammoFlag & c_valid; }

	// FUNCTION: BETA10 0x100177b0
	Mx3DPointFloat* GetUnknown0x160() { return m_eq; }

	// FUNCTION: BETA10 0x100177e0
	MxFloat* GetUnknown0x19c() { return &m_unk0x19c; }

	// FUNCTION: BETA10 0x1001fbd0
	void SetValid(MxBool p_valid)
	{
		if (p_valid) {
			m_ammoFlag |= c_valid;
		}
		else {
			m_ammoFlag &= ~c_valid;
		}
	}

	// FUNCTION: BETA10 0x1001fc80
	MxU32 IsPizza() { return m_ammoFlag & c_pizza; }

	// FUNCTION: BETA10 0x10021d60
	MxU32 IsDonut() { return m_ammoFlag & c_donut; }

	// FUNCTION: BETA10 0x1001fcb0
	void SetBit4(MxBool p_bit4)
	{
		if (p_bit4) {
			m_ammoFlag |= c_bit4;
		}
		else {
			m_ammoFlag &= ~c_bit4;
		}
	}

	// FUNCTION: BETA10 0x10021d90
	MxU32 IsBit4() { return m_ammoFlag & c_bit4; }

	void SetBit5(MxBool p_bit5)
	{
		if (p_bit5) {
			m_ammoFlag |= c_bit5;
		}
		else {
			m_ammoFlag &= ~c_bit5;
		}
	}

	MxU32 IsBit5() { return m_ammoFlag & c_bit5; }

	MxFloat GetUnknown0x158() { return m_unk0x158; }

	void SetUnknown0x158(MxFloat p_unk0x158) { m_unk0x158 = p_unk0x158; }

	MxResult Remove();
	MxResult Create(Act3* p_world, MxU32 p_isPizza, MxS32 p_index);
	MxResult FUN_10053b40(Vector3& p_srcLoc, Vector3& p_srcDir, Vector3& p_srcUp);
	MxResult FUN_10053cb0(LegoPathController* p_p, LegoPathBoundary* p_boundary, MxFloat p_unk0x19c);
	MxResult FUN_10053d30(LegoPathController* p_p, MxFloat p_unk0x19c);

	// SYNTHETIC: LEGO1 0x10053880
	// Act3Ammo::`scalar deleting destructor'

private:
	MxResult FUN_10053db0(float p_param1, const Matrix4& p_param2);

	static Mx3DPointFloat g_unk0x10104f08;

	MxU16 m_ammoFlag;       // 0x154
	MxFloat m_unk0x158;     // 0x158
	Act3* m_world;          // 0x15c
	Mx3DPointFloat m_eq[3]; // 0x160
	MxFloat m_unk0x19c;     // 0x19c
};

#endif // ACT3AMMO_H
