#ifndef LEGOACTORPRESENTER_H
#define LEGOACTORPRESENTER_H

#include "legoentitypresenter.h"

// VTABLE: LEGO1 0x100d5320
// SIZE 0x50
class LegoActorPresenter : public LegoEntityPresenter {
public:
	// LegoActorPresenter() {}

	// FUNCTION: LEGO1 0x100679c0
	~LegoActorPresenter() override {}

	// FUNCTION: LEGO1 0x1000cb10
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f06a4
		return "LegoActorPresenter";
	}

	// FUNCTION: LEGO1 0x1000cb20
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoActorPresenter::ClassName()) || LegoEntityPresenter::IsA(p_name);
	}

	void ReadyTickle() override;    // vtable+0x18
	void StartingTickle() override; // vtable+0x1c
	void ParseExtra() override;     // vtable+0x30
};

// SYNTHETIC: LEGO1 0x1000cc30
// LegoActorPresenter::`scalar deleting destructor'

#endif // LEGOACTORPRESENTER_H
