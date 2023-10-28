#ifndef LEGOHIDEANIMPRESENTER_H
#define LEGOHIDEANIMPRESENTER_H

#include "legoloopinganimpresenter.h"

// VTABLEADDR 0x100d9278
// SIZE 0xc4
class LegoHideAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoHideAnimPresenter();

	// OFFSET: LEGO1 0x1006d880
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f06cc
		return "LegoHideAnimPresenter";
	}

	// OFFSET: LEGO1 0x1006d890
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, ClassName()) || LegoAnimPresenter::IsA(name);
	}

private:
	void Init();
};

#endif // LEGOHIDEANIMPRESENTER_H
