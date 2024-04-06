#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

#include "decomp.h"
#include "misc/legostorage.h"
#include "mxcore.h"

class LegoEntity;
class LegoROI;

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
	static void SetCustomizeAnimFile(const char* p_value);

	void Init();
	void FUN_1002fa00();
	void FUN_1002fb30();
	MxResult Save(LegoStorage* p_storage);
	MxResult Load(LegoStorage* p_storage);
	MxBool FUN_1002fdb0(LegoEntity* p_entity);
	MxU32 FUN_1002ff40(LegoROI*, MxBool);
	void FUN_10030000(LegoEntity* p_entity);
	void FUN_10030590();

	// SYNTHETIC: LEGO1 0x1002f940
	// LegoBuildingManager::`scalar deleting destructor'

private:
	static char* g_customizeAnimFile;

	undefined m_unk0x08[0x28]; // 0x08
};

#endif // LEGOBUILDINGMANAGER_H
