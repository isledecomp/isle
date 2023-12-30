#ifndef LEGOTEXTUREPRESENTER_H
#define LEGOTEXTUREPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4d90
// SIZE 0x54 (from inlined construction at 0x10009bb5)
class LegoTexturePresenter : public MxMediaPresenter {
public:
	virtual ~LegoTexturePresenter() override;

	// FUNCTION: LEGO1 0x1000ce50
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0664
		return "LegoTexturePresenter";
	}

	// FUNCTION: LEGO1 0x1000ce60
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoTexturePresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	virtual void DoneTickle() override;       // vtable+0x2c
	virtual MxResult AddToManager() override; // vtable+0x34
	virtual MxResult PutData() override;      // vtable+0x4c
};

#endif // LEGOTEXTUREPRESENTER_H
