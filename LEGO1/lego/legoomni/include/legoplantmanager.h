#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "decomp.h"
#include "mxcore.h"

class LegoEntity;
class LegoPathBoundary;
struct LegoPlantInfo;
class LegoROI;
class LegoStorage;
class LegoWorld;

// VTABLE: LEGO1 0x100d6758
// SIZE 0x2c
class LegoPlantManager : public MxCore {
public:
	// SIZE 0x0c
	struct AnimEntry {
		LegoEntity* m_entity; // 0x00
		LegoROI* m_roi;       // 0x04
		MxLong m_time;        // 0x08
	};

	LegoPlantManager();
	~LegoPlantManager() override; // vtable+0x00

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10026290
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f318c
		return "LegoPlantManager";
	}

	void Init();
	void LoadWorldInfo(MxS32 p_worldId);
	void Reset(MxS32 p_worldId);
	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	MxBool SwitchColor(LegoEntity* p_entity);
	MxBool SwitchVariant(LegoEntity* p_entity);
	MxBool SwitchSound(LegoEntity* p_entity);
	MxBool SwitchMove(LegoEntity* p_entity);
	MxBool SwitchMood(LegoEntity* p_entity);
	MxU32 GetAnimationId(LegoEntity* p_entity);
	MxU32 GetSoundId(LegoEntity* p_entity, MxBool p_state);
	LegoPlantInfo* GetInfoArray(MxS32& p_length);
	MxBool FUN_10026c50(LegoEntity* p_entity);
	void ScheduleAnimation(LegoEntity* p_entity, MxLong p_length);
	MxResult FUN_10026410();
	void FUN_10027120();
	void FUN_10027200();

	static void SetCustomizeAnimFile(const char* p_value);
	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

	// SYNTHETIC: LEGO1 0x100262a0
	// LegoPlantManager::`scalar deleting destructor'

private:
	LegoEntity* CreatePlant(MxS32 p_index, LegoWorld* p_world, MxS32 p_worldId);
	void RemovePlant(MxS32 p_index, MxS32 p_worldId);
	void FUN_10026860(MxS32 p_index);
	LegoPlantInfo* GetInfo(LegoEntity* p_entity);
	MxBool FUN_10026c80(MxS32 p_index);
	void FUN_100271b0(LegoEntity* p_entity, MxS32 p_adjust);

	static char* g_customizeAnimFile;
	static MxS32 g_maxMove[4];
	static MxU32 g_maxSound;

	MxS32 m_worldId;         // 0x08
	undefined m_unk0x0c;     // 0x0c
	AnimEntry* m_entries[5]; // 0x10
	MxS8 m_numEntries;       // 0x24
	LegoWorld* m_world;      // 0x28
};

#endif // LEGOPLANTMANAGER_H
