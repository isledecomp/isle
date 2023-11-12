#ifndef LEGOTEXTUREPRESENTER_H
#define LEGOTEXTUREPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE 0x100d4d90
// SIZE 0x54 (from inlined construction at 0x10009bb5)
class LegoTexturePresenter : public MxMediaPresenter {
public:
	virtual ~LegoTexturePresenter() override;

	// OFFSET: LEGO1 0x1000ce50
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0664
		return "LegoTexturePresenter";
	}

	// OFFSET: LEGO1 0x1000ce60
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoTexturePresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}

	virtual MxResult AddToManager() override; // vtable+0x34
};

#endif // LEGOTEXTUREPRESENTER_H
