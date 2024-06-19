#include "legoplantmanager.h"

#include "legocharactermanager.h"
#include "legoentity.h"
#include "legoplants.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legostorage.h"
#include "scripts.h"
#include "sndanim_actions.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(LegoPlantManager, 0x2c)

// GLOBAL: LEGO1 0x100f1660
const char* g_plantLodNames[4][5] = {
	{"flwrwht", "flwrblk", "flwryel", "flwrred", "flwrgrn"},
	{"treewht", "treeblk", "treeyel", "treered", "tree"},
	{"bushwht", "bushblk", "bushyel", "bushred", "bush"},
	{"palmwht", "palmblk", "palmyel", "palmred", "palm"}
};

// GLOBAL: LEGO1 0x100f16b0
float g_unk0x100f16b0[] = {0.1f, 0.7f, 0.5f, 0.9f};

// GLOBAL: LEGO1 0x100f16c0
MxU8 g_unk0x100f16c0[] = {1, 2, 2, 3};

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

	m_worldId = -1;
	m_unk0x0c = 0;
	m_unk0x24 = 0;
}

// FUNCTION: LEGO1 0x10026360
// FUNCTION: BETA10 0x100c5032
void LegoPlantManager::LoadWorldInfo(MxS32 p_worldId)
{
	m_worldId = p_worldId;
	LegoWorld* world = CurrentWorld();

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		CreatePlant(i, world, p_worldId);
	}

	m_unk0x0c = 0;
}

// FUNCTION: LEGO1 0x100263a0
void LegoPlantManager::Reset(MxS32 p_worldId)
{
	MxU32 i;
	DeleteObjects(g_sndAnimScript, SndanimScript::c_AnimC1, SndanimScript::c_AnimBld18);

	for (i = 0; i < m_unk0x24; i++) {
		delete m_unk0x10[i];
	}

	m_unk0x24 = 0;

	for (i = 0; i < sizeOfArray(g_plantInfo); i++) {
		RemovePlant(i, p_worldId);
	}

	m_worldId = -1;
	m_unk0x0c = 0;
}

// FUNCTION: LEGO1 0x10026590
// FUNCTION: BETA10 0x100c561e
LegoEntity* LegoPlantManager::CreatePlant(MxS32 p_index, LegoWorld* p_world, MxS32 p_worldId)
{
	LegoEntity* entity = NULL;

	if (p_index < sizeOfArray(g_plantInfo)) {
		MxU32 world = 1 << (MxU8) p_worldId;

		if (g_plantInfo[p_index].m_worlds & world && g_plantInfo[p_index].m_unk0x16 != 0) {
			if (g_plantInfo[p_index].m_entity == NULL) {
				char name[256];
				char lodName[256];

				sprintf(name, "plant%d", p_index);
				sprintf(lodName, "%s", g_plantLodNames[g_plantInfo[p_index].m_variant][g_plantInfo[p_index].m_color]);

				LegoROI* roi = CharacterManager()->CreateAutoROI(name, lodName, TRUE);
				roi->SetVisibility(TRUE);

				entity = roi->GetEntity();
				entity->SetLocation(
					g_plantInfo[p_index].m_position,
					g_plantInfo[p_index].m_direction,
					g_plantInfo[p_index].m_up,
					FALSE
				);
				entity->SetType(LegoEntity::e_plant);
				g_plantInfo[p_index].m_entity = entity;
			}
			else {
				entity = g_plantInfo[p_index].m_entity;
			}
		}
	}

	return entity;
}

// FUNCTION: LEGO1 0x100266c0
// FUNCTION: BETA10 0x100c5859
void LegoPlantManager::RemovePlant(MxS32 p_index, MxS32 p_worldId)
{
	if (p_index < sizeOfArray(g_plantInfo)) {
		MxU32 world = 1 << (MxU8) p_worldId;

		if (g_plantInfo[p_index].m_worlds & world && g_plantInfo[p_index].m_entity != NULL) {
			CharacterManager()->ReleaseAutoROI(g_plantInfo[p_index].m_entity->GetROI());
			g_plantInfo[p_index].m_entity = NULL;
		}
	}
}

// FUNCTION: LEGO1 0x10026720
// FUNCTION: BETA10 0x100c5918
MxResult LegoPlantManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		LegoPlantInfo* info = &g_plantInfo[i];

		if (p_storage->Write(&info->m_variant, sizeof(info->m_variant)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_color, sizeof(info->m_color)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_initialUnk0x16, sizeof(info->m_initialUnk0x16)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100267b0
// FUNCTION: BETA10 0x100c5a76
MxResult LegoPlantManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		LegoPlantInfo* info = &g_plantInfo[i];

		if (p_storage->Read(&info->m_variant, sizeof(info->m_variant)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_color, sizeof(info->m_color)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_unk0x16, sizeof(info->m_unk0x16)) != SUCCESS) {
			goto done;
		}

		info->m_initialUnk0x16 = info->m_unk0x16;
		FUN_10026860(i);
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x10026860
// FUNCTION: BETA10 0x100c5be0
void LegoPlantManager::FUN_10026860(MxS32 p_index)
{
	MxU8 variant = g_plantInfo[p_index].m_variant;

	if (g_plantInfo[p_index].m_unk0x16 >= 0) {
		float value = g_unk0x100f16c0[variant] - g_plantInfo[p_index].m_unk0x16;
		g_plantInfo[p_index].m_position[1] = g_plantInfoInit[p_index].m_position[1] - value * g_unk0x100f16b0[variant];
	}
	else {
		g_plantInfo[p_index].m_position[1] = g_plantInfoInit[p_index].m_position[1];
	}
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
