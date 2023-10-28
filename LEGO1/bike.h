#ifndef BIKE_H
#define BIKE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLEADDR 0x100d9808
// SIZE 0x164
class Bike : public IslePathActor {
public:
	Bike();

	// OFFSET: LEGO1 0x100766f0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f03d0
		return "Bike";
	}

	// OFFSET: LEGO1 0x10076700
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Bike::ClassName()) || IslePathActor::IsA(name);
	}

private:
	// TODO: Bike fields
	undefined m_unk160[4];
};

#endif // BIKE_H
