#ifndef LEGOMODELPRESENTER_H
#define LEGOMODELPRESENTER_H

#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100d4e50
// SIZE 0x6c (discovered through inline constructor at 0x10009ae6)
class LegoModelPresenter : public MxVideoPresenter {
public:
	__declspec(dllexport) static void configureLegoModelPresenter(int param_1);

	// FUNCTION: LEGO1 0x1000ccb0
	inline const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f067c
		return "LegoModelPresenter";
	}

	// FUNCTION: LEGO1 0x1000ccc0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoModelPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}
};

#endif // LEGOMODELPRESENTER_H
