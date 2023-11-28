#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"
#include "mxunklist.h"

// VTABLE: LEGO1 0x100dc618
// SIZE 0x4c
class MxCompositePresenter : public MxPresenter {
public:
	MxCompositePresenter();
	virtual ~MxCompositePresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x100b6210
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0774
		return "MxCompositePresenter";
	}

	// FUNCTION: LEGO1 0x100b6220
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxCompositePresenter::ClassName()) || MxPresenter::IsA(name);
	}

	virtual void VTable0x58();
	virtual void VTable0x5c();
	virtual void VTable0x60(undefined4 p_unknown);
	virtual MxBool VTable0x64(undefined4 p_unknown);

private:
	MxUnkList m_list;
};

#endif // MXCOMPOSITEPRESENTER_H
