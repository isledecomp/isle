#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d6758
// SIZE 0x2c
class LegoPlantManager : public MxCore {
public:
	LegoPlantManager();
	~LegoPlantManager() override; // vtable+0x00

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10026290
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f318c
		return "LegoPlantManager";
	}

	void FUN_10026360(undefined4 p_world);
	void FUN_100263a0(undefined4 p_und);
	void FUN_10027120();

	// SYNTHETIC: LEGO1 0x100262a0
	// LegoPlantManager::`scalar deleting destructor'

private:
	void Init();
};

#endif // LEGOPLANTMANAGER_H
