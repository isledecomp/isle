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
		c_withoutBoundary = 0x08,
		c_sharkFood = 0x10
	};

	Act3Ammo();
	~Act3Ammo() override;

	void Destroy(MxBool p_fromDestructor) override; // vtable+0x1c
	void Animate(float p_time) override;            // vtable+0x70

	// FUNCTION: BETA10 0x10017750
	MxU32 IsValid() { return m_ammoFlag & c_valid; }

	// FUNCTION: BETA10 0x100177b0
	Mx3DPointFloat* GetCoefficients() { return m_coefficients; }

	// FUNCTION: BETA10 0x100177e0
	MxFloat* GetApexParameter() { return &m_apexParameter; }

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
	void SetShootWithoutBoundary(MxBool p_withoutBoundary)
	{
		if (p_withoutBoundary) {
			m_ammoFlag |= c_withoutBoundary;
		}
		else {
			m_ammoFlag &= ~c_withoutBoundary;
		}
	}

	// FUNCTION: BETA10 0x10021d90
	MxU32 IsShootWithoutBoundary() { return m_ammoFlag & c_withoutBoundary; }

	void SetSharkFood(MxBool p_sharkFood)
	{
		if (p_sharkFood) {
			m_ammoFlag |= c_sharkFood;
		}
		else {
			m_ammoFlag &= ~c_sharkFood;
		}
	}

	MxU32 IsSharkFood() { return m_ammoFlag & c_sharkFood; }

	MxFloat GetRotateTimeout() { return m_rotateTimeout; }

	void SetRotateTimeout(MxFloat p_rotateTimeout) { m_rotateTimeout = p_rotateTimeout; }

	MxResult Remove();
	MxResult Create(Act3* p_world, MxU32 p_isPizza, MxS32 p_index);
	MxResult CalculateArc(const Vector3& p_srcLoc, const Vector3& p_srcDir, const Vector3& p_srcUp);
	MxResult Shoot(LegoPathController* p_p, LegoPathBoundary* p_boundary, MxFloat p_apexParameter);
	MxResult Shoot(LegoPathController* p_p, MxFloat p_apexParameter);

	// SYNTHETIC: LEGO1 0x10053880
	// Act3Ammo::`scalar deleting destructor'

private:
	MxResult CalculateTransformOnCurve(float p_curveParameter, Matrix4& p_transform);

	static Mx3DPointFloat g_hitTranslation;

	MxU16 m_ammoFlag;                 // 0x154
	MxFloat m_rotateTimeout;          // 0x158
	Act3* m_world;                    // 0x15c
	Mx3DPointFloat m_coefficients[3]; // 0x160
	MxFloat m_apexParameter;          // 0x19c
};

#endif // ACT3AMMO_H
