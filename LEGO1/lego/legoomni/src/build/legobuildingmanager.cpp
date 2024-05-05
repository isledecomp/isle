#include "legobuildingmanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legoentity.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legostorage.h"

DECOMP_SIZE_ASSERT(LegoBuildingManager, 0x30)

struct LegoBuildingData {
	LegoEntity* m_pEntity;
	const char* m_hausName;
	MxU32 m_cycle1;
	MxU32 m_cycle2;
	MxU8 m_cycle3;
	MxS8 m_unk0x11;
	MxS8 m_initialUnk0x11; // = initial value loaded to m_unk0x11
	MxU8 m_flags;
	float m_float;
	char m_unk0x18[16];
	undefined4 m_unk0x28;
};

DECOMP_SIZE_ASSERT(LegoBuildingData, 0x2c);

// GLOBAL: LEGO1 0x100f3410
const char* g_buildingDataHausName[5] = {
	"haus1",
	"haus4",
	"haus5",
	"haus6",
	"haus7",
};

// clang-format off
// GLOBAL: LEGO1 0x100f3428
float g_buildingDataDownshiftScale[16] = {
	0.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
};

// GLOBAL: LEGO1 0x100f3468
MxU8 g_buildingDataDownshift[16] = {
	5, 5, 5, 5,
	3, 5, 5, 5,
	3, 5, 5, 5,
	5, 5, 5, 5,
};
// clang-format on

// GLOBAL: LEGO1 0x100f3478
LegoBuildingData g_buildingDataTemplate[16];

// GLOBAL: LEGO1 0x100f3738
MxU32 g_buildingCycle1Length = 6;

// GLOBAL: LEGO1 0x100f37c8
char* LegoBuildingManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x100f37cc
int g_buildingManagerConfig = 1;

// GLOBAL: LEGO1 0x10104c30
LegoBuildingData g_buildingData[16];

// Unclear what the offset of this global is.
int g_buildingCycle2Length[16];

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

// FUNCTION: LEGO1 0x1002f960
LegoBuildingManager::~LegoBuildingManager()
{
	delete g_customizeAnimFile;
}

// FUNCTION: LEGO1 0x1002f9d0
void LegoBuildingManager::Init()
{
	for (MxS32 i = 0; i < _countof(g_buildingData); i++) {
		g_buildingData[i] = g_buildingDataTemplate[i];
	}

	m_nextVariant = 0;
	m_unk0x09 = 0;
	m_unk0x20 = 0;
	m_unk0x24 = 0;
	m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x1002fa00
void LegoBuildingManager::FUN_1002fa00()
{
	MxS32 i = 0;
	LegoWorld* world = CurrentWorld();
	for (; i < _countof(g_buildingData); i++) {
		UpdatePosition(i, world);
	}
	if (g_buildingManagerConfig <= 1) {
		LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingDataHausName[0]);
		if (entity) {
			entity->GetROI()->SetVisibility(TRUE);
			m_unk0x09 = 0;
			return;
		}
	}
	else {
		for (i = 0; i < _countof(g_buildingDataHausName); i++) {
			LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingDataHausName[i]);
			if (entity)
				entity->GetROI()->SetVisibility(m_nextVariant == i);
		}
	}
	m_unk0x09 = 0;
}

// FUNCTION: LEGO1 0x1002fa90
void LegoBuildingManager::UpdatePosition(int p_index, LegoWorld* p_world)
{
	LegoEntity* entity = (LegoEntity*) p_world->Find("MxEntity", g_buildingData[p_index].m_hausName);
	if (entity) {
		entity->SetType(3);
		g_buildingData[p_index].m_pEntity = entity;
		LegoROI* roi = entity->GetROI();
		AdjustHeight(p_index);
		MxMatrix mat = roi->GetLocal2World();
		mat.SetY(g_buildingData[p_index].m_float);
		roi->FUN_100a46b0(mat);
		VideoManager()->Get3DManager()->GetLego3DView()->Moved(*roi);
	}
}

// STUB: LEGO1 0x1002fb30
void LegoBuildingManager::FUN_1002fb30()
{
	// TODO
}

// FUNCTION: LEGO1 0x1002fb80
MxResult LegoBuildingManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;
	for (MxS32 i = 0; i < _countof(g_buildingData); i++) {
		LegoBuildingData* data = &g_buildingData[i];
		if (p_storage->Write(&data->m_cycle1, 4) != SUCCESS)
			goto done;
		if (p_storage->Write(&data->m_cycle2, 4) != SUCCESS)
			goto done;
		if (p_storage->Write(&data->m_cycle3, 1) != SUCCESS)
			goto done;
		if (p_storage->Write(&data->m_initialUnk0x11, 1) != SUCCESS)
			goto done;
	}
	if (p_storage->Write(&m_nextVariant, 1) != SUCCESS)
		goto done;

	result = SUCCESS;
done:
	return result;
}

// FUNCTION: LEGO1 0x1002fc10
MxResult LegoBuildingManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;
	for (MxS32 i = 0; i < _countof(g_buildingData); i++) {
		LegoBuildingData* data = &g_buildingData[i];

		if (p_storage->Read(&data->m_cycle1, 4) != SUCCESS)
			goto done;
		if (p_storage->Read(&data->m_cycle2, 4) != SUCCESS)
			goto done;
		if (p_storage->Read(&data->m_cycle3, 1) != SUCCESS)
			goto done;
		if (p_storage->Read(&data->m_unk0x11, 1) != SUCCESS)
			goto done;
		data->m_initialUnk0x11 = data->m_unk0x11;
		AdjustHeight(i);
	}

	if (p_storage->Read(&m_nextVariant, 1) != SUCCESS)
		goto done;

	if (g_buildingManagerConfig <= 1)
		m_nextVariant = 0;

	result = SUCCESS;
done:
	return result;
}

// FUNCTION: LEGO1 0x1002fcc0
void LegoBuildingManager::AdjustHeight(int p_i)
{
	// Not close assembly yet.
	// Does not use any member variables but we can be sure that
	// this is a THISCALL method because LegoBuildingManager::Read
	// goes to the trouble of restoring ECX before calling it.
	MxS8 value = g_buildingData[p_i].m_unk0x11;
	if (value > 0) {
		g_buildingData[p_i].m_float = g_buildingDataTemplate[p_i].m_float -
									  (g_buildingDataDownshift[p_i] - value) * g_buildingDataDownshiftScale[p_i];
	}
	else if (value == 0) {
		g_buildingData[p_i].m_float =
			g_buildingDataTemplate[p_i].m_float - g_buildingDataDownshift[p_i] * g_buildingDataDownshiftScale[p_i];
		if (g_buildingData[p_i].m_pEntity != NULL) {
			LegoROI* roi = g_buildingData[p_i].m_pEntity->GetROI();
			if (roi != NULL)
				roi->SetVisibility(FALSE);
		}
	}
	else {
		g_buildingData[p_i].m_float = g_buildingDataTemplate[p_i].m_float;
	}
}

// FUNCTION: LEGO1 0x1002fd70
LegoBuildingData* LegoBuildingManager::GetData(LegoEntity* p_entity)
{
	MxS32 i;
	for (i = 0; i < _countof(g_buildingData); i++) {
		if (g_buildingData[i].m_pEntity == p_entity)
			break;
	}
	if (i < _countof(g_buildingData))
		return &g_buildingData[i];
	return NULL;
}

// FUNCTION: LEGO1 0x1002fdb0
MxBool LegoBuildingManager::IncrementVariant(LegoEntity* p_entity)
{
	if (g_buildingManagerConfig <= 1)
		return TRUE;

	LegoBuildingData* data = GetData(p_entity);
	if (data != NULL && (data->m_flags & 1) && data->m_unk0x11 == -1) {
		LegoROI* roi = p_entity->GetROI();
		if (++m_nextVariant >= _countof(g_buildingDataHausName))
			m_nextVariant = 0;

		roi->SetVisibility(FALSE);
		data->m_hausName = g_buildingDataHausName[m_nextVariant];
		UpdatePosition(12, CurrentWorld());
		if (data->m_pEntity != NULL)
			data->m_pEntity->GetROI()->SetVisibility(TRUE);
		return TRUE;
	}
	return FALSE;
}

// FUNCTION: LEGO1 0x1002fe40
MxBool LegoBuildingManager::FUN_1002fe40(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingData* data = GetData(p_entity);
	if (data != NULL && (data->m_flags & 2)) {
		data->m_cycle1++;
		if (data->m_cycle1 >= g_buildingCycle1Length) {
			data->m_cycle1 = 0;
		}
		result = TRUE;
	}
	return result;
}

// FUNCTION: LEGO1 0x1002fe80
MxBool LegoBuildingManager::FUN_1002fe80(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingData* data = GetData(p_entity);
	if (data != NULL && (data->m_flags & 4)) {
		data->m_cycle2++;
		if (data->m_cycle2 >= g_buildingCycle2Length[data - g_buildingData]) {
			data->m_cycle2 = 0;
		}
		result = TRUE;
	}
	return result;
}

// FUNCTION: LEGO1 0x1002fed0
MxBool LegoBuildingManager::FUN_1002fed0(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingData* data = GetData(p_entity);
	if (data != NULL && (data->m_flags & 8)) {
		data->m_cycle3++;
		if (data->m_cycle3 > 3) {
			data->m_cycle3 = 0;
		}
		result = TRUE;
	}
	return result;
}

// STUB: LEGO1 0x1002ff40
MxU32 LegoBuildingManager::FUN_1002ff40(LegoEntity*, MxBool)
{
	// TODO
	return 0;
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

// FUNCTION: LEGO1 0x10030000
MxBool LegoBuildingManager::FUN_10030000(LegoEntity* p_entity)
{
	LegoBuildingData* data = GetData(p_entity);
	if (data == NULL)
		return FALSE;

	return FUN_10030030(data - g_buildingData);
}

// STUB: LEGO1 0x10030030
MxBool LegoBuildingManager::FUN_10030030(int p_index)
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10030110
MxBool LegoBuildingManager::FUN_10030110(LegoBuildingData* p_data)
{
	for (MxS32 i = 0; i < _countof(g_buildingData); i++) {
		if (&g_buildingData[i] == p_data) {
			return FUN_10030030(i);
		}
	}
	return FALSE;
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
