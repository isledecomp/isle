#include "legoplantmanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legocharactermanager.h"
#include "legoentity.h"
#include "legoplants.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legostorage.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "scripts.h"
#include "sndanim_actions.h"
#include "viewmanager/viewmanager.h"

#include <stdio.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(LegoPlantManager, 0x2c)
DECOMP_SIZE_ASSERT(LegoPlantManager::AnimEntry, 0x0c)

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

// GLOBAL: LEGO1 0x100f315c
MxU32 LegoPlantManager::g_maxSound = 8;

// GLOBAL: LEGO1 0x100f3160
MxU32 g_unk0x100f3160 = 56;

// GLOBAL: LEGO1 0x100f3164
MxU32 g_unk0x100f3164 = 66;

// GLOBAL: LEGO1 0x100f3168
MxS32 LegoPlantManager::g_maxMove[4] = {3, 3, 3, 3};

// GLOBAL: LEGO1 0x100f3178
MxU32 g_plantAnimationId[4] = {30, 33, 36, 39};

// GLOBAL: LEGO1 0x100f3188
// GLOBAL: BETA10 0x101f4e70
char* LegoPlantManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10103180
// GLOBAL: BETA10 0x1020f4c0
LegoPlantInfo g_plantInfo[81];

// FUNCTION: LEGO1 0x10026220
LegoPlantManager::LegoPlantManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100262c0
// FUNCTION: BETA10 0x100c5002
LegoPlantManager::~LegoPlantManager()
{
	delete[] g_customizeAnimFile;
}

// FUNCTION: LEGO1 0x10026330
// FUNCTION: BETA10 0x100c4f90
void LegoPlantManager::Init()
{
	// In BETA10 this appears to be LegoPlantManager::LegoPlantManager()

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i] = g_plantInfoInit[i];
	}

	m_worldId = LegoOmni::e_undefined;
	m_unk0x0c = 0;
	m_numEntries = 0;
}

// FUNCTION: LEGO1 0x10026360
// FUNCTION: BETA10 0x100c5032
void LegoPlantManager::LoadWorldInfo(LegoOmni::World p_worldId)
{
	m_worldId = p_worldId;
	LegoWorld* world = CurrentWorld();

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		CreatePlant(i, world, p_worldId);
	}

	m_unk0x0c = 0;
}

// FUNCTION: LEGO1 0x100263a0
// FUNCTION: BETA10 0x100c5093
void LegoPlantManager::Reset(LegoOmni::World p_worldId)
{
	MxU32 i;
	DeleteObjects(g_sndAnimScript, SndanimScript::c_AnimC1, SndanimScript::c_AnimBld18);

	for (i = 0; i < m_numEntries; i++) {
		delete m_entries[i];
	}

	m_numEntries = 0;

	for (i = 0; i < sizeOfArray(g_plantInfo); i++) {
		RemovePlant(i, p_worldId);
	}

	m_worldId = LegoOmni::e_undefined;
	m_unk0x0c = 0;
}

// FUNCTION: LEGO1 0x10026410
// FUNCTION: BETA10 0x100c50e9
MxResult LegoPlantManager::FUN_10026410()
{
	// similar to LegoBuildingManager::FUN_10030630()

	LegoWorld* world = CurrentWorld();

	if (world == NULL) {
		return FAILURE;
	}

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		if (g_plantInfo[i].m_entity != NULL && g_plantInfo[i].m_name != NULL) {
			g_plantInfo[i].m_boundary = world->FindPathBoundary(g_plantInfo[i].m_name);

			if (g_plantInfo[i].m_boundary != NULL) {
				Mx3DPointFloat position(g_plantInfo[i].m_x, g_plantInfo[i].m_y, g_plantInfo[i].m_z);
				LegoPathBoundary* boundary = g_plantInfo[i].m_boundary;

				for (MxS32 j = 0; j < boundary->GetNumEdges(); j++) {
					Mx4DPointFloat* normal = boundary->GetEdgeNormal(j);

					if (position.Dot(normal, &position) + (*normal).index_operator(3) < -0.001) {
						MxTrace(
							"Plant %d shot location (%g, %g, %g) is not in boundary %s.\n",
							i,
							position[0],
							position[1],
							position[2],
							boundary->GetName()
						);
						g_plantInfo[i].m_boundary = NULL;
						break;
					}
				}

				if (g_plantInfo[i].m_boundary != NULL) {
					Mx4DPointFloat& unk0x14 = *g_plantInfo[i].m_boundary->GetUnknown0x14();

					if (position.Dot(&position, &unk0x14) + unk0x14.index_operator(3) > 0.001 ||
						position.Dot(&position, &unk0x14) + unk0x14.index_operator(3) < -0.001) {

						g_plantInfo[i].m_y =
							-((position[0] * unk0x14.index_operator(0) + unk0x14.index_operator(3) +
							   position[2] * unk0x14.index_operator(2)) /
							  unk0x14.index_operator(1));

						MxTrace(
							"Plant %d shot location (%g, %g, %g) is not on plane of boundary %s...adjusting to (%g, "
							"%g, "
							"%g)\n",
							i,
							position[0],
							position[1],
							position[2],
							g_plantInfo[i].m_boundary->GetName(),
							position[0],
							g_plantInfo[i].m_y,
							position[2]
						);
					}
				}
			}
			else {
				MxTrace("Plant %d is in boundary %s that does not exist.\n", i, g_plantInfo[i].m_name);
			}
		}
	}

	m_unk0x0c = TRUE;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10026570
// FUNCTION: BETA10 0x100c55e0
LegoPlantInfo* LegoPlantManager::GetInfoArray(MxS32& p_length)
{
	if (!m_unk0x0c) {
		FUN_10026410();
	}

	p_length = sizeOfArray(g_plantInfo);
	return g_plantInfo;
}

// FUNCTION: LEGO1 0x10026590
// FUNCTION: BETA10 0x100c561e
LegoEntity* LegoPlantManager::CreatePlant(MxS32 p_index, LegoWorld* p_world, LegoOmni::World p_worldId)
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
void LegoPlantManager::RemovePlant(MxS32 p_index, LegoOmni::World p_worldId)
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

// FUNCTION: LEGO1 0x100268d0
// FUNCTION: BETA10 0x100c5c7a
MxS32 LegoPlantManager::GetNumPlants()
{
	return sizeOfArray(g_plantInfo);
}

// FUNCTION: LEGO1 0x100268e0
// FUNCTION: BETA10 0x100c5c95
LegoPlantInfo* LegoPlantManager::GetInfo(LegoEntity* p_entity)
{
	MxS32 i;

	for (i = 0; i < sizeOfArray(g_plantInfo); i++) {
		if (g_plantInfo[i].m_entity == p_entity) {
			break;
		}
	}

	if (i < sizeOfArray(g_plantInfo)) {
		return &g_plantInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10026920
// FUNCTION: BETA10 0x100c5dc9
MxBool LegoPlantManager::SwitchColor(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL) {
		return FALSE;
	}

	LegoROI* roi = p_entity->GetROI();
	info->m_color++;

	if (info->m_color > LegoPlantInfo::e_green) {
		info->m_color = LegoPlantInfo::e_white;
	}

	ViewLODList* lodList = GetViewLODListManager()->Lookup(g_plantLodNames[info->m_variant][info->m_color]);

	if (roi->GetUnknown0xe0() >= 0) {
		VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(roi);
	}

	roi->SetLODList(lodList);
	lodList->Release();
	CharacterManager()->FUN_10085870(roi);
	return TRUE;
}

// FUNCTION: LEGO1 0x100269e0
// FUNCTION: BETA10 0x100c5ee2
MxBool LegoPlantManager::SwitchVariant(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL || info->m_unk0x16 != -1) {
		return FALSE;
	}

	LegoROI* roi = p_entity->GetROI();
	info->m_variant++;

	if (info->m_variant > LegoPlantInfo::e_palm) {
		info->m_variant = LegoPlantInfo::e_flower;
	}

	ViewLODList* lodList = GetViewLODListManager()->Lookup(g_plantLodNames[info->m_variant][info->m_color]);

	if (roi->GetUnknown0xe0() >= 0) {
		VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(roi);
	}

	roi->SetLODList(lodList);
	lodList->Release();
	CharacterManager()->FUN_10085870(roi);

	if (info->m_move != 0 && info->m_move >= g_maxMove[info->m_variant]) {
		info->m_move = g_maxMove[info->m_variant] - 1;
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x10026ad0
// FUNCTION: BETA10 0x100c6049
MxBool LegoPlantManager::SwitchSound(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_sound++;

		if (info->m_sound >= g_maxSound) {
			info->m_sound = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b00
// FUNCTION: BETA10 0x100c60a7
MxBool LegoPlantManager::SwitchMove(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_move++;

		if (info->m_move >= g_maxMove[info->m_variant]) {
			info->m_move = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b40
// FUNCTION: BETA10 0x100c610e
MxBool LegoPlantManager::SwitchMood(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_mood++;

		if (info->m_mood > 3) {
			info->m_mood = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b70
// FUNCTION: BETA10 0x100c6168
MxU32 LegoPlantManager::GetAnimationId(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		return g_plantAnimationId[info->m_variant] + info->m_move;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10026ba0
// FUNCTION: BETA10 0x100c61ba
MxU32 LegoPlantManager::GetSoundId(LegoEntity* p_entity, MxBool p_state)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (p_state) {
		return (info->m_mood & 1) + g_unk0x100f3164;
	}

	if (info != NULL) {
		return info->m_sound + g_unk0x100f3160;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10026be0
// FUNCTION: BETA10 0x100c62bc
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

// FUNCTION: LEGO1 0x10026c50
// FUNCTION: BETA10 0x100c6349
MxBool LegoPlantManager::FUN_10026c50(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL) {
		return FALSE;
	}

	return FUN_10026c80(info - g_plantInfo);
}

// FUNCTION: LEGO1 0x10026c80
// FUNCTION: BETA10 0x100c63eb
MxBool LegoPlantManager::FUN_10026c80(MxS32 p_index)
{
	if (p_index >= sizeOfArray(g_plantInfo)) {
		return FALSE;
	}

	LegoPlantInfo* info = &g_plantInfo[p_index];

	if (info == NULL) {
		return FALSE;
	}

	MxBool result = TRUE;

	if (info->m_unk0x16 < 0) {
		info->m_unk0x16 = g_unk0x100f16c0[info->m_variant];
	}

	if (info->m_unk0x16 > 0) {
		LegoROI* roi = info->m_entity->GetROI();
		info->m_unk0x16--;

		if (info->m_unk0x16 == 1) {
			info->m_unk0x16 = 0;
		}

		if (info->m_unk0x16 == 0) {
			roi->SetVisibility(FALSE);
		}
		else {
			FUN_10026860(info - g_plantInfo);
			info->m_entity->SetLocation(info->m_position, info->m_direction, info->m_up, FALSE);
		}
	}
	else {
		result = FALSE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026d70
void LegoPlantManager::ScheduleAnimation(LegoEntity* p_entity, MxLong p_length)
{
	m_world = CurrentWorld();

	if (m_numEntries == 0) {
		TickleManager()->RegisterClient(this, 50);
	}

	AnimEntry* entry = m_entries[m_numEntries] = new AnimEntry;
	m_numEntries++;

	entry->m_entity = p_entity;
	entry->m_roi = p_entity->GetROI();
	entry->m_time = Timer()->GetTime() + p_length + 1000;
	FUN_100271b0(p_entity, -1);
}

// FUNCTION: LEGO1 0x10026e00
MxResult LegoPlantManager::Tickle()
{
	MxLong time = Timer()->GetTime();

	if (m_numEntries != 0) {
		for (MxS32 i = 0; i < m_numEntries; i++) {
			AnimEntry** ppEntry = &m_entries[i];
			AnimEntry* entry = *ppEntry;

			if (m_world != CurrentWorld() || !entry->m_entity) {
				delete entry;
				m_numEntries--;

				if (m_numEntries != i) {
					m_entries[i] = m_entries[m_numEntries];
					m_entries[m_numEntries] = NULL;
				}

				break;
			}

			if (entry->m_time - time > 1000) {
				break;
			}

			MxMatrix local90;
			MxMatrix local48;

			MxMatrix locald8(entry->m_roi->GetLocal2World());
			Mx3DPointFloat localec(locald8[3]);

			ZEROVEC3(locald8[3]);

			locald8[1][0] = sin(((entry->m_time - time) * 2) * 0.0062832f) * 0.2;
			locald8[1][2] = sin(((entry->m_time - time) * 4) * 0.0062832f) * 0.2;
			locald8.Scale(1.03f, 0.95f, 1.03f);

			SET3(locald8[3], localec);

			entry->m_roi->FUN_100a58f0(locald8);
			entry->m_roi->VTable0x14();

			if (entry->m_time < time) {
				LegoPlantInfo* info = GetInfo(entry->m_entity);

				if (info->m_unk0x16 == 0) {
					entry->m_roi->SetVisibility(FALSE);
				}
				else {
					FUN_10026860(info - g_plantInfo);
					info->m_entity->SetLocation(info->m_position, info->m_direction, info->m_up, FALSE);
				}

				delete entry;
				m_numEntries--;

				if (m_numEntries != i) {
					i--;
					*ppEntry = m_entries[m_numEntries];
					m_entries[m_numEntries] = NULL;
				}
			}
		}
	}
	else {
		TickleManager()->UnregisterClient(this);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10027120
void LegoPlantManager::FUN_10027120()
{
	LegoWorld* world = CurrentWorld();

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i].m_unk0x16 = -1;
		g_plantInfo[i].m_initialUnk0x16 = -1;
		FUN_10026860(i);

		if (g_plantInfo[i].m_entity != NULL) {
			g_plantInfo[i].m_entity->SetLocation(
				g_plantInfo[i].m_position,
				g_plantInfo[i].m_direction,
				g_plantInfo[i].m_up,
				FALSE
			);
		}
	}
}

// FUNCTION: LEGO1 0x100271b0
void LegoPlantManager::FUN_100271b0(LegoEntity* p_entity, MxS32 p_adjust)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		if (info->m_unk0x16 < 0) {
			info->m_unk0x16 = g_unk0x100f16c0[info->m_variant];
		}

		if (info->m_unk0x16 > 0) {
			info->m_unk0x16 += p_adjust;
			if (info->m_unk0x16 <= 1 && p_adjust < 0) {
				info->m_unk0x16 = 0;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10027200
void LegoPlantManager::FUN_10027200()
{
	for (MxU32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i].m_initialUnk0x16 = g_plantInfo[i].m_unk0x16;
	}
}
