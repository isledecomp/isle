#ifndef LEGOLOOPINGANIMPRESENTER_H
#define LEGOLOOPINGANIMPRESENTER_H

#include "legoanimpresenter.h"

// VTABLE: LEGO1 0x100d4900
// SIZE 0xc0 (discovered through inlined constructor at 0x10009ecd)
class LegoLoopingAnimPresenter : public LegoAnimPresenter {
public:
	// FUNCTION: LEGO1 0x1000c9a0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0700
		return "LegoLoopingAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1000c9b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoAnimPresenter::IsA(p_name);
	}
};

#endif // LEGOLOOPINGANIMPRESENTER_H
