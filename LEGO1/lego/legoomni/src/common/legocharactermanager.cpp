#include "legocharactermanager.h"

#include "legogamestate.h"
#include "mxmisc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoCharacterManager, 0x08)
DECOMP_SIZE_ASSERT(LegoSaveDataEntry3, 0x108)

// GLOBAL: LEGO1 0x100f80c0
LegoSaveDataEntry3 g_saveDataInit[66]; // TODO: add data

// GLOBAL: LEGO1 0x100fc4e4
char* LegoCharacterManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10104f20
LegoSaveDataEntry3 g_saveData3[66];

// FUNCTION: LEGO1 0x10082a20
LegoCharacterManager::LegoCharacterManager()
{
	m_map = new LegoUnkSaveDataMap();
	InitSaveData();

	m_customizeAnimFile = new CustomizeAnimFileVariable("CUSTOMIZE_ANIM_FILE");
	VariableTable()->SetVariable(m_customizeAnimFile);
}

// FUNCTION: LEGO1 0x10083270
void LegoCharacterManager::InitSaveData()
{
	for (MxS32 i = 0; i < 66; i++) {
		g_saveData3[i] = g_saveDataInit[i];
	}
}

// STUB: LEGO1 0x100832a0
void LegoCharacterManager::FUN_100832a0()
{
	// TODO
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoCharacterManager::WriteSaveData3(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	// This should probably be a for loop but I can't figure out how to
	// make it match as a for loop.
	LegoSaveDataEntry3* entry = g_saveData3;
	const LegoSaveDataEntry3* end = &g_saveData3[66];

	while (TRUE) {
		if (p_storage->Write(&entry->m_savePart1, 4) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart2, 4) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart3, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_currentFrame, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart5, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart6, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart7, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart8, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart9, 1) != SUCCESS) {
			break;
		}
		if (p_storage->Write(&entry->m_savePart10, 1) != SUCCESS) {
			break;
		}
		if (++entry >= end) {
			result = SUCCESS;
			break;
		}
	}

	return result;
}

// STUB: LEGO1 0x100833f0
MxResult LegoCharacterManager::ReadSaveData3(LegoStorage* p_storage)
{
	return SUCCESS;
}

// STUB: LEGO1 0x10083500
LegoROI* LegoCharacterManager::FUN_10083500(const char* p_key, MxBool p_option)
{
	// TODO
	// involves an STL map with a _Nil node at 0x100fc508
	return NULL;
}

// STUB: LEGO1 0x10083db0
void LegoCharacterManager::FUN_10083db0(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x10083f10
void LegoCharacterManager::FUN_10083f10(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x10084c00
MxBool LegoCharacterManager::FUN_10084c00(const LegoChar*)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10084ec0
MxBool LegoCharacterManager::FUN_10084ec0(LegoROI* p_roi)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10085140
MxU32 LegoCharacterManager::FUN_10085140(LegoROI*, MxBool)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100851a0
void LegoCharacterManager::SetCustomizeAnimFile(const char* p_value)
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

// STUB: LEGO1 0x10085210
LegoROI* LegoCharacterManager::FUN_10085210(const LegoChar*, LegoChar*, undefined)
{
	return NULL;
}

// FUNCTION: LEGO1 0x10085a80
LegoROI* LegoCharacterManager::FUN_10085a80(LegoChar* p_und1, LegoChar* p_und2, undefined p_und3)
{
	return FUN_10085210(p_und1, p_und2, p_und3);
}
