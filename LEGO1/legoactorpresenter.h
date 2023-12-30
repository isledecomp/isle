#ifndef LEGOACTORPRESENTER_H
#define LEGOACTORPRESENTER_H

#include "legoentitypresenter.h"

// VTABLE: LEGO1 0x100d5320
// SIZE 0x50
class LegoActorPresenter : public LegoEntityPresenter {
public:
	// FUNCTION: LEGO1 0x1000cb10
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f06a4
		return "LegoActorPresenter";
	}

	// FUNCTION: LEGO1 0x1000cb20
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoActorPresenter::ClassName()) || LegoEntityPresenter::IsA(p_name);
	}
};

#endif // LEGOACTORPRESENTER_H
