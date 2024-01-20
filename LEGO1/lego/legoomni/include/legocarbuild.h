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

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x10022a60
	// LegoCarBuild::`scalar deleting destructor'
};

#endif // LEGOCARBUILD_H
