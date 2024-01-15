#ifndef LEGOHIDEANIMPRESENTER_H
#define LEGOHIDEANIMPRESENTER_H

#include "legoloopinganimpresenter.h"

// VTABLE: LEGO1 0x100d9278
// SIZE 0xc4
class LegoHideAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoHideAnimPresenter();
	virtual ~LegoHideAnimPresenter() override;

	// FUNCTION: LEGO1 0x1006d880
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f06cc
		return "LegoHideAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1006d890
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

private:
	void Init();
};

// SYNTHETIC: LEGO1 0x1006d9d0
// LegoHideAnimPresenter::`scalar deleting destructor'

#endif // LEGOHIDEANIMPRESENTER_H
