#ifndef LEGOLOCOMOTIONANIMPRESENTER_H
#define LEGOLOCOMOTIONANIMPRESENTER_H

#include "legoloopinganimpresenter.h"

// VTABLE: LEGO1 0x100d9170
class LegoLocomotionAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoLocomotionAnimPresenter();

	// FUNCTION: LEGO1 0x1006ce50
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f06e4
		return "LegoLocomotionAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1006ce60
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoLoopingAnimPresenter::IsA(p_name);
	}

private:
	void Init();
};

#endif // LEGOLOCOMOTIONANIMPRESENTER_H
