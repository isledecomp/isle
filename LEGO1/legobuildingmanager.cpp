#include "legobuildingmanager.h"

// 0x100f37cc
int g_buildingManagerConfig = 1;

// OFFSET: LEGO1 0x1002f8b0
void LegoBuildingManager::configureLegoBuildingManager(int param_1)
{
	g_buildingManagerConfig = param_1;
}

// OFFSET: LEGO1 0x1002f8c0
LegoBuildingManager::LegoBuildingManager()
{
	Init();
}

// OFFSET: LEGO1 0x1002f960 STUB
LegoBuildingManager::~LegoBuildingManager()
{
	// TODO
}

// OFFSET: LEGO1 0x1002f9d0 STUB
void LegoBuildingManager::Init()
{
	// TODO
}
