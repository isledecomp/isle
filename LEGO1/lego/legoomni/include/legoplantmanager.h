#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "decomp.h"
#include "misc/legostorage.h"
#include "mxcore.h"

class LegoEntity;
class LegoROI;

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

	void Init();
	void FUN_10026360(MxS32 p_scriptIndex);
	void FUN_100263a0(undefined4 p_und);
	void Save(LegoStorage* p_storage);
	MxResult Load(LegoStorage* p_storage);
	MxBool FUN_100269e0(LegoEntity* p_entity);
	MxU32 FUN_10026ba0(LegoROI*, MxBool);
	void FUN_10026c50(LegoEntity* p_entity);
	void FUN_10027120();

	static void SetCustomizeAnimFile(const char* p_value);

	// SYNTHETIC: LEGO1 0x100262a0
	// LegoPlantManager::`scalar deleting destructor'

private:
	static char* g_customizeAnimFile;

	undefined m_unk0x08[0x24]; // 0x08
};

#endif // LEGOPLANTMANAGER_H
