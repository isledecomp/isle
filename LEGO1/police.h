#ifndef POLICE_H
#define POLICE_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d8a80
// SIZE 0x110
// Radio at 0xf8
class Police : public LegoWorld {
public:
	Police();
	virtual ~Police() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x1005e1e0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0450
		return "Police";
	}

	// FUNCTION: LEGO1 0x1005e1f0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Police::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // POLICE_H
