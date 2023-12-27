#ifndef LEGOANIMMMPRESENTER_H
#define LEGOANIMMMPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE: LEGO1 0x100d7de8
// SIZE 0x74
class LegoAnimMMPresenter : public MxCompositePresenter {
public:
	LegoAnimMMPresenter();

	// FUNCTION: LEGO1 0x1004a950
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f046c
		return "LegoAnimMMPresenter";
	}

	// FUNCTION: LEGO1 0x1004a960
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimMMPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}
};

#endif // LEGOANIMMMPRESENTER_H
