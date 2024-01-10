#ifndef LEGOCAMERACONTROLLER_H
#define LEGOCAMERACONTROLLER_H

#include "legopointofviewcontroller.h"
#include "mxcore.h"
#include "mxpoint32.h"
#include "realtime/matrix.h"
#include "realtime/vector.h"

// VTABLE: LEGO1 0x100d57b0
// SIZE 0xc8
class LegoCameraController : public LegoPointOfViewController {
public:
	LegoCameraController();
	virtual ~LegoCameraController() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+04

	// FUNCTION: LEGO1 0x10011ec0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0850
		return "LegoCameraController";
	}

	// FUNCTION: LEGO1 0x10011ed0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxCore::IsA(p_name);
	}

	virtual void OnLButtonDown(MxPoint32 p_point);                // vtable+0x30
	virtual void OnLButtonUp(MxPoint32 p_point);                  // vtable+0x34
	virtual void OnRButtonDown(MxPoint32 p_point);                // vtable+0x38
	virtual void OnRButtonUp(MxPoint32 p_point);                  // vtable+0x3c
	virtual void OnMouseMove(MxU8 p_modifier, MxPoint32 p_point); // vtable+0x40
	virtual MxResult Create();                                    // vtable+0x44

	void SetWorldTransform(const Vector3Impl& p_at, const Vector3Impl& p_dir, const Vector3Impl& p_up);
	void FUN_100123e0(Matrix4Data& p_transform, MxU32);
	Vector3Data& FUN_10012740();
	Vector3Data& FUN_100127f0();
	Vector3Data& FUN_100128a0();

private:
	Matrix4Data m_matrix1; // 0x38
	Matrix4Data m_matrix2; // 0x80
};

// SYNTHETIC: LEGO1 0x10011f50
// LegoCameraController::`scalar deleting destructor'

#endif // LEGOCAMERACONTROLLER_H
