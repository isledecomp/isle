#ifndef BUMPBOUY_H
#define BUMPBOUY_H

#include "legoanimactor.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d6790 LegoPathActor
// VTABLE: LEGO1 0x100d6860 LegoAnimActor
// VTABLE: BETA10 0x101b9430 LegoPathActor
// VTABLE: BETA10 0x101b9520 LegoAnimActor
// SIZE 0x174
class BumpBouy : public LegoAnimActor {
public:
	BumpBouy();
	~BumpBouy() override;
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100274f0
	// FUNCTION: BETA10 0x10026790
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0394
		return "BumpBouy";
	}

	// FUNCTION: LEGO1 0x10027510
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BumpBouy::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x100274a0
	// BumpBouy::`scalar deleting destructor'
};

// GLOBAL: LEGO1 0x100d6788
// BumpBouy::`vbtable'

#endif // BUMPBOUY_H
