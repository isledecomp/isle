#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100d6f50
// SIZE 0x30
class LegoBuildingManager : public MxCore {
public:
	LegoBuildingManager();
	~LegoBuildingManager() override;

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1002f930
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f37d0
		return "LegoBuildingManager";
	}

	static void configureLegoBuildingManager(MxS32);

	void FUN_1002fa00();
	void FUN_1002fb30();
	void FUN_10030590();

	// SYNTHETIC: LEGO1 0x1002f940
	// LegoBuildingManager::`scalar deleting destructor'

private:
	void Init();
};

#endif // LEGOBUILDINGMANAGER_H
