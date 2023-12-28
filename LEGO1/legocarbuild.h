#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d6658
// SIZE 0x34c
class LegoCarBuild : public LegoWorld {
public:
	LegoCarBuild();
	virtual ~LegoCarBuild() override;

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x10022940
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0504
		return "LegoCarBuild";
	}

	// FUNCTION: LEGO1 0x10022950
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuild::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // LEGOCARBUILD_H
