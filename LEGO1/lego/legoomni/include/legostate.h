#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "decomp.h"
#include "legostream.h"
#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d46c0
class LegoState : public MxCore {
public:
	virtual ~LegoState() override; // vtable+0x00

	// FUNCTION: LEGO1 0x100060d0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01b8
		return "LegoState";
	}

	// FUNCTION: LEGO1 0x100060e0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoState::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxBool VTable0x14();                                   // vtable+0x14
	virtual MxBool SetFlag();                                      // vtable+0x18
	virtual MxResult VTable0x1c(LegoFileStream* p_legoFileStream); // vtable+0x1C
};

#endif // LEGOSTATE_H
