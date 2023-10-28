#ifndef INFOCENTER_H
#define INFOCENTER_H

#include "legoworld.h"

// VTABLEADDR 0x100d9338
// SIZE 0x1d8
class Infocenter : public LegoWorld {
public:
	Infocenter();
	virtual ~Infocenter() override;

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4
	virtual MxResult Tickle() override;         // vtable+0x8

	// OFFSET: LEGO1 0x1006eb40
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f04ec
		return "Infocenter";
	}

	// OFFSET: LEGO1 0x1006eb50
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Infocenter::ClassName()) || LegoWorld::IsA(name);
	}
};

#endif // INFOCENTER_H
