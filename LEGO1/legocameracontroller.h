#ifndef LEGOCAMERACONTROLLER_H
#define LEGOCAMERACONTROLLER_H

#include "mxcore.h"

// VTABLE 0x100d57b0
// SIZE 0xc8
class LegoCameraController : public MxCore {
public:
	LegoCameraController();
	virtual ~LegoCameraController() override; // vtable+0x0

	// OFFSET: LEGO1 0x10011ec0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0850
		return "LegoCameraController";
	}

	// OFFSET: LEGO1 0x10011ed0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, ClassName()) || MxCore::IsA(name);
	}
};

#endif // LEGOCAMERACONTROLLER_H
