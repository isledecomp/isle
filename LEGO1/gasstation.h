#ifndef GASSTATION_H
#define GASSTATION_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d4650
// SIZE 0x128
// Radio variable at 0x46, in constructor
class GasStation : public LegoWorld {
public:
	GasStation();
	virtual ~GasStation() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x10004780
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0168
		return "GasStation";
	}

	// FUNCTION: LEGO1 0x10004790
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStation::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // GASSTATION_H
