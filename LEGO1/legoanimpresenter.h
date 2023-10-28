#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "mxvideopresenter.h"

// VTABLEADDR 0x100d90c8
class LegoAnimPresenter : public MxVideoPresenter {
public:
	LegoAnimPresenter();

	// OFFSET: LEGO1 0x10068530
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f071c
		return "LegoAnimPresenter";
	}

	// OFFSET: LEGO1 0x10068540
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}

private:
	void Init();
};

#endif // LEGOANIMPRESENTER_H
