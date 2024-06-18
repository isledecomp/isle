#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "decomp.h"
#include "mxcore.h"

class LegoEntity;
class LegoPathBoundary;
class LegoROI;
class LegoStorage;
class LegoWorld;

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
	void LoadWorldInfo(MxS32 p_worldId);
	void FUN_100263a0(undefined4 p_und);
	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	MxBool SwitchColor(LegoEntity* p_entity);
	MxBool SwitchVariant(LegoEntity* p_entity);
	MxBool SwitchSound(LegoEntity* p_entity);
	MxBool SwitchMove(LegoEntity* p_entity);
	MxBool SwitchMood(LegoEntity* p_entity);
	MxU32 FUN_10026b70(LegoEntity* p_entity);
	MxU32 FUN_10026ba0(LegoEntity* p_entity, MxBool);
	void FUN_10026c50(LegoEntity* p_entity);
	void FUN_10027120();

	static void SetCustomizeAnimFile(const char* p_value);
	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

	// SYNTHETIC: LEGO1 0x100262a0
	// LegoPlantManager::`scalar deleting destructor'

private:
	LegoEntity* CreatePlant(MxS32 p_index, LegoWorld* p_world, MxS32 p_worldId);

	static char* g_customizeAnimFile;

	MxS32 m_worldId;           // 0x08
	undefined m_unk0x0c;       // 0x0c
	undefined m_unk0x10[0x17]; // 0x10
	undefined m_unk0x24;       // 0x24
	undefined4 m_unk0x28;      // 0x28
};

#endif // LEGOPLANTMANAGER_H
