#include "legoplantmanager.h"

#include "legoentity.h"

DECOMP_SIZE_ASSERT(LegoPlantManager, 0x2c)

// GLOBAL: LEGO1 0x100f3188
char* LegoPlantManager::g_customizeAnimFile = NULL;

// FUNCTION: LEGO1 0x10026220
LegoPlantManager::LegoPlantManager()
{
	Init();
}

// STUB: LEGO1 0x100262c0
LegoPlantManager::~LegoPlantManager()
{
	// TODO
}

// STUB: LEGO1 0x10026330
void LegoPlantManager::Init()
{
	// TODO
}

// STUB: LEGO1 0x10026360
void LegoPlantManager::FUN_10026360(MxS32 p_scriptIndex)
{
	// TODO
}

// STUB: LEGO1 0x100263a0
void LegoPlantManager::FUN_100263a0(undefined4 p_und)
{
	// TODO
}

// STUB: LEGO1 0x10026720
void LegoPlantManager::Save(LegoStorage* p_storage)
{
	// TODO
}

// STUB: LEGO1 0x100267b0
MxResult LegoPlantManager::Load(LegoStorage* p_storage)
{
	return SUCCESS;
}

// STUB: LEGO1 0x100269e0
MxBool LegoPlantManager::FUN_100269e0(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10026ba0
MxU32 LegoPlantManager::FUN_10026ba0(LegoROI*, MxBool)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10026be0
void LegoPlantManager::SetCustomizeAnimFile(const char* p_value)
{
	if (g_customizeAnimFile != NULL) {
		delete[] g_customizeAnimFile;
	}

	if (p_value != NULL) {
		g_customizeAnimFile = new char[strlen(p_value) + 1];

		if (g_customizeAnimFile != NULL) {
			strcpy(g_customizeAnimFile, p_value);
		}
	}
	else {
		g_customizeAnimFile = NULL;
	}
}

// STUB: LEGO1 0x10026e00
MxResult LegoPlantManager::Tickle()
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10027120
void LegoPlantManager::FUN_10027120()
{
	// TODO
}
