#include "legobuildingmanager.h"

DECOMP_SIZE_ASSERT(LegoBuildingManager, 0x30)

// GLOBAL: LEGO1 0x100f37c8
char* LegoBuildingManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x100f37cc
int g_buildingManagerConfig = 1;

// FUNCTION: LEGO1 0x1002f8b0
void LegoBuildingManager::configureLegoBuildingManager(MxS32 p_buildingManagerConfig)
{
	g_buildingManagerConfig = p_buildingManagerConfig;
}

// FUNCTION: LEGO1 0x1002f8c0
LegoBuildingManager::LegoBuildingManager()
{
	Init();
}

// STUB: LEGO1 0x1002f960
LegoBuildingManager::~LegoBuildingManager()
{
	// TODO
}

// STUB: LEGO1 0x1002f9d0
void LegoBuildingManager::Init()
{
	// TODO
}

// STUB: LEGO1 0x1002fa00
void LegoBuildingManager::FUN_1002fa00()
{
	// TODO
}

// STUB: LEGO1 0x1002fb30
void LegoBuildingManager::FUN_1002fb30()
{
	// TODO
}

// STUB: LEGO1 0x1002fb80
MxResult LegoBuildingManager::Save(LegoStorage* p_storage)
{
	return SUCCESS;
}

// STUB: LEGO1 0x1002fc10
MxResult LegoBuildingManager::Load(LegoStorage* p_storage)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002ff90
void LegoBuildingManager::SetCustomizeAnimFile(const char* p_value)
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

// STUB: LEGO1 0x10030220
MxResult LegoBuildingManager::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10030590
void LegoBuildingManager::FUN_10030590()
{
	// TODO
}
