#include "legoplantmanager.h"

#include "legoentity.h"
#include "legoplants.h"

DECOMP_SIZE_ASSERT(LegoPlantManager, 0x2c)
DECOMP_SIZE_ASSERT(LegoPlantInfo, 0x54)

// GLOBAL: LEGO1 0x100f3188
char* LegoPlantManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10103180
LegoPlantInfo g_plantInfo[81];

// FUNCTION: LEGO1 0x10026220
LegoPlantManager::LegoPlantManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100262c0
LegoPlantManager::~LegoPlantManager()
{
	delete[] g_customizeAnimFile;
}

// FUNCTION: LEGO1 0x10026330
// FUNCTION: BETA10 0x100c4f90
void LegoPlantManager::Init()
{
	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i] = g_plantInfoInit[i];
	}

	m_unk0x08 = -1;
	m_unk0x0c = 0;
	m_unk0x24 = 0;
}

// STUB: LEGO1 0x10026360
// FUNCTION: BETA10 0x100c5032
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
// FUNCTION: BETA10 0x100c5918
MxResult LegoPlantManager::Write(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100267b0
// FUNCTION: BETA10 0x100c5a76
MxResult LegoPlantManager::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10026920
MxBool LegoPlantManager::SwitchColor(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x100269e0
MxBool LegoPlantManager::SwitchVariant(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10026ad0
MxBool LegoPlantManager::SwitchSound(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10026b00
MxBool LegoPlantManager::SwitchMove(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10026b40
MxBool LegoPlantManager::SwitchMood(LegoEntity* p_entity)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10026b70
MxU32 LegoPlantManager::FUN_10026b70(LegoEntity* p_entity)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10026ba0
MxU32 LegoPlantManager::FUN_10026ba0(LegoEntity* p_entity, MxBool)
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

// STUB: LEGO1 0x10026c50
void LegoPlantManager::FUN_10026c50(LegoEntity* p_entity)
{
	// TODO
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
