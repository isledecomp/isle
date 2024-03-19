#include "legocharactermanager.h"

#include "legoanimactor.h"
#include "legogamestate.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoCharacter, 0x08)
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
	m_characters = new LegoCharacterMap();
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

// FUNCTION: LEGO1 0x10083500
LegoROI* LegoCharacterManager::GetROI(const char* p_key, MxBool p_createEntity)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it = m_characters->find(p_key);

	if (it != m_characters->end()) {
		character = (*it).second;
		character->AddRef();
	}

	if (character == NULL) {
		LegoROI* roi = CreateROI(p_key);
		roi->SetUnknown0x0c(0);

		if (roi != NULL) {
			character = new LegoCharacter(roi);
			char* key = new char[strlen(p_key) + 1];

			if (key != NULL) {
				strcpy(key, p_key);
				(*m_characters)[key] = character;
				VideoManager()->Get3DManager()->Add(*roi);
			}
		}
	}
	else {
		VideoManager()->Get3DManager()->Remove(*character->m_roi);
		VideoManager()->Get3DManager()->Add(*character->m_roi);
	}

	if (character != NULL) {
		if (p_createEntity && character->m_roi->GetEntity() == NULL) {
			LegoAnimActor* actor = new LegoAnimActor(1);

			actor->SetROI(character->m_roi, FALSE, FALSE);
			actor->FUN_100114e0(0);
			actor->SetFlag(LegoActor::c_bit2);
			FUN_10084c60(p_key)->m_actor = actor;
		}

		return character->m_roi;
	}

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

// STUB: LEGO1 0x10084030
LegoROI* LegoCharacterManager::CreateROI(const char* p_key)
{
	return NULL;
}

// STUB: LEGO1 0x10084c00
MxBool LegoCharacterManager::FUN_10084c00(const LegoChar*)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10084c60
LegoSaveDataEntry3* LegoCharacterManager::FUN_10084c60(const char* p_key)
{
	return NULL;
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
