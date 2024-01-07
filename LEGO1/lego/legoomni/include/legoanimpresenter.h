#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100d90c8
class LegoAnimPresenter : public MxVideoPresenter {
public:
	LegoAnimPresenter();

	// FUNCTION: LEGO1 0x10068530
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068540
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

private:
	void Init();
};

#endif // LEGOANIMPRESENTER_H
