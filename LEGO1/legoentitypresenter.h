#ifndef LEGOENTITYPRESENTER_H
#define LEGOENTITYPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE 0x100d8398
class LegoEntityPresenter : public MxCompositePresenter {
public:
	LegoEntityPresenter();
	virtual ~LegoEntityPresenter() override; // vtable+0x0

	// OFFSET: LEGO1 0x100534b0
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f06b8
		return "LegoEntityPresenter";
	}

	// OFFSET: LEGO1 0x100534c0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoEntityPresenter::ClassName()) || MxCompositePresenter::IsA(name);
	}

private:
	void Init();
};

#endif // LEGOENTITYPRESENTER_H
