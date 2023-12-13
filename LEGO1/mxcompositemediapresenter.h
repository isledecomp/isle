#ifndef MXCOMPOSITEMEDIAPRESENTER_H
#define MXCOMPOSITEMEDIAPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE: LEGO1 0x100dc618
// SIZE 0x50
class MxCompositeMediaPresenter : public MxCompositePresenter {
public:
	MxCompositeMediaPresenter();

	// FUNCTION: LEGO1 0x10073f10
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f02d4
		return "MxCompositeMediaPresenter";
	}

	// FUNCTION: LEGO1 0x10073f20
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxCompositeMediaPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}
};

#endif // MXCOMPOSITEMEDIAPRESENTER_H
