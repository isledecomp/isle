#ifndef LEGOPARTPRESENTER_H
#define LEGOPARTPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4df0
// SIZE 0x54 (from inlined construction at 0x10009fac)
class LegoPartPresenter : public MxMediaPresenter {
public:
	// FUNCTION: LEGO1 0x1000cf70
	inline const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f05d8
		return "LegoPartPresenter";
	}

	// FUNCTION: LEGO1 0x1000cf80
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoPartPresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}

	__declspec(dllexport) static void configureLegoPartPresenter(int param_1, int param_2);
};

#endif // LEGOPARTPRESENTER_H
