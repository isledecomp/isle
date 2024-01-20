#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d6758
// SIZE 0x2c
class LegoPlantManager : public MxCore {
public:
	LegoPlantManager();
	virtual ~LegoPlantManager() override; // vtable+0x0

	virtual MxResult Tickle() override; // vtable+0x8

	// FUNCTION: LEGO1 0x10026290
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f318c
		return "LegoPlantManager";
	}

	void FUN_10026360(undefined4 p_world);

	// SYNTHETIC: LEGO1 0x100262a0
	// LegoPlantManager::`scalar deleting destructor'

private:
	void Init();
};

#endif // LEGOPLANTMANAGER_H
