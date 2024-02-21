#include "legoplantmanager.h"

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
