#ifndef LEGOACTIONCONTROLPRESENTER_H
#define LEGOACTIONCONTROLPRESENTER_H

#include "mxmediapresenter.h"

// VTABLEADDR 0x100d5118
// SIZE 0x68
class LegoActionControlPresenter : public MxMediaPresenter {
public:
	// OFFSET: LEGO1 0x1000d0e0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f05bc
		return "LegoActionControlPresenter";
	}

	// OFFSET: LEGO1 0x1000d0f0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoActionControlPresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}
};

#endif // LEGOACTIONCONTROLPRESENTER_H
