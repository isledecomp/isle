#ifndef LEGOCAMERACONTROLLER_H
#define LEGOCAMERACONTROLLER_H

#include "mxcore.h"
#include "realtime/matrix.h"
#include "realtime/vector.h"

// VTABLE: LEGO1 0x100d57b0
// SIZE 0xc8
class LegoCameraController : public MxCore {
public:
	LegoCameraController();
	virtual ~LegoCameraController() override; // vtable+0x0

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

	void LookAt(Vector3Impl& p_at, Vector3Impl& p_dir, Vector3Impl& p_up);
	void FUN_100123e0(Matrix4Data& p_transform, MxU32);
	Vector3Data& FUN_10012740();
	Vector3Data& FUN_100127f0();
	Vector3Data& FUN_100128a0();
};

#endif // LEGOCAMERACONTROLLER_H
