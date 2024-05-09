#include "legobuildingmanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legocachesoundmanager.h"
#include "legoentity.h"
#include "legopathboundary.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoBuildingManager, 0x30)
DECOMP_SIZE_ASSERT(LegoBuildingInfo, 0x2c)
DECOMP_SIZE_ASSERT(LegoBuildingManager::AnimEntry, 0x14)

// GLOBAL: LEGO1 0x100f3410
const char* g_buildingInfoHausName[5] = {
	"haus1",
	"haus4",
	"haus5",
	"haus6",
	"haus7",
};

// clang-format off
// GLOBAL: LEGO1 0x100f3428
float g_buildingInfoDownshiftScale[16] = {
	0.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
	1.0f, 1.0f, 1.0f, 1.0f,
};

// GLOBAL: LEGO1 0x100f3468
MxU8 g_buildingInfoDownshift[16] = {
	5, 5, 5, 5,
	3, 5, 5, 5,
	3, 5, 5, 5,
	5, 5, 5, 5,
};

// GLOBAL: LEGO1 0x100f3478
LegoBuildingInfo g_buildingInfoInit[16] = {
	{
		NULL, "infocen",
		4, 0, 1,
		-1, -1, 0x00,
		8.99999f,
		"edg02_74",
		84.79617f, 9.0f, -10.2189f,
		NULL,
	},
	{
		NULL, "policsta",
		4, 0, 1,
		-1, -1, 0x10,
		0.999992f,
		"int33",
		67.28488, 1.0f, -85.3917,
		NULL,
	},
	{
		NULL, "Jail",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"edg02_50",
		93.245659f, 0.0f, -48.7773f,
		NULL,
	},
	{
		NULL, "races",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"int14",
		-21.7321f, 0.0f, 11.23354f,
		NULL,
	},
	{
		NULL, "medcntr",
		4, 0, 1,
		-1, -1, 0x10,
		3.99071f,
		"edg02_27",
		86.020737f, 4.0f, 31.35498f,
		NULL,
	},
	{
		NULL, "gas",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"int24",
		26.32025f, 0.0f, -2.28938f,
		NULL,
	},
	{
		NULL, "beach",
		4, 0, 1,
		-1, -1, 0x10,
		-1.8125f,
		"edg00_46",
		14.375f, -1.3125f, -56.75f,
		NULL,
	},
	{
		NULL, "racef",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"edg03_03",
		-4.15951f, 0.0f, 5.2003198f,
		NULL,
	},
	{
		NULL, "racej",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"edg03_03",
		-4.15951f, 0.0f, 5.2003198f,
		NULL,
	},
	{
		NULL, "Store",
		4, 0, 1,
		-1, -1, 0x3e,
		2.0f,
		"edg02_60",
		-49.4744f, 2.0f, -56.6276f,
		NULL,
	},
	{
		NULL, "Bank",
		4, 0, 1,
		-1, -1, 0x3e,
		0.0f,
		"edg02_36",
		18.53531f, 0.0f, -16.6053f,
		NULL,
	},
	{
		NULL, "Post",
		4, 0, 1,
		-1, -1, 0x3e,
		0.0f,
		"edg02_58",
		-33.5413f, 0.0f, -55.1791f,
		NULL,
	},
	{
		NULL, "haus1",
		4, 0, 1,
		-1, -1, 0x3f,
		7.0625f,
		"int11",
		-62.7827f, 7.0f, -45.2215f,
		NULL,
	},
	{
		NULL, "haus2",
		4, 0, 1,
		-1, -1, 0x3e,
		8.0f,
		"int07",
		-69.2376f, 8.0f, -6.8008099f,
		NULL,
	},
	{
		NULL, "haus3",
		4, 0, 1,
		-1, -1, 0x3e,
		7.0f,
		"edg01_24",
		-69.0596f, 7.0f, -24.4928f,
		NULL,
	},
	{
		NULL, "Pizza",
		4, 0, 1,
		-1, -1, 0x10,
		0.0f,
		"int37",
		-17.9438f, 0.0f, -46.827999f,
		NULL,
	},
};
// clang-format on

// GLOBAL: LEGO1 0x100f3738
MxU32 g_buildingCycle1Length = 6;

// GLOBAL: LEGO1 0x100f373c
MxU32 g_cycleLengthOffset1 = 0x3c;

// GLOBAL: LEGO1 0x100f3740
MxU32 g_cycleLengthOffset3 = 0x42;

// clang-format off
// GLOBAL: LEGO1 0x100f3788
MxU32 g_buildingEntityId[16] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x46, 0x49, 0x4c,
	0x4f, 0x52, 0x55, 0x00,
};
// clang-format on

// GLOBAL: LEGO1 0x100f37c8
char* LegoBuildingManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x100f37cc
MxS32 g_buildingManagerConfig = 1;

// GLOBAL: LEGO1 0x10104c30
LegoBuildingInfo g_buildingInfo[16];

// GLOBAL: LEGO1 0x100f3748
MxS32 g_buildingCycle2Length[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0};

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
	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		g_buildingInfo[i] = g_buildingInfoInit[i];
	}

	m_nextVariant = 0;
	m_unk0x09 = 0;
	m_numEntries = 0;
	m_sound = NULL;
	m_unk0x28 = FALSE;
}

// FUNCTION: LEGO1 0x1002fa00
// FUNCTION: BETA10 0x10063ad1
void LegoBuildingManager::FUN_1002fa00()
{
	MxS32 i;
	LegoWorld* world = CurrentWorld();

	for (i = 0; i < _countof(g_buildingInfo); i++) {
		UpdatePosition(i, world);
	}

	if (g_buildingManagerConfig <= 1) {
		LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingInfoHausName[0]);
		if (entity) {
			entity->GetROI()->SetVisibility(TRUE);
			m_unk0x09 = 0;
		}
	}
	else {
		for (i = 0; i < _countof(g_buildingInfoHausName); i++) {
			LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingInfoHausName[i]);
			if (entity) {
				entity->GetROI()->SetVisibility(m_nextVariant == i);
			}
		}
	}

	m_unk0x09 = 0;
}

// FUNCTION: LEGO1 0x1002fa90
// FUNCTION: BETA10 0x10063b88
void LegoBuildingManager::UpdatePosition(MxS32 p_index, LegoWorld* p_world)
{
	LegoEntity* entity = (LegoEntity*) p_world->Find("MxEntity", g_buildingInfo[p_index].m_hausName);

	if (entity) {
		entity->SetType(LegoEntity::e_building);
		g_buildingInfo[p_index].m_entity = entity;
		LegoROI* roi = entity->GetROI();
		AdjustHeight(p_index);
		MxMatrix mat = roi->GetLocal2World();
		mat[3][1] = g_buildingInfo[p_index].m_unk0x014;
		roi->FUN_100a46b0(mat);
		VideoManager()->Get3DManager()->Moved(*roi);
	}
}

// FUNCTION: LEGO1 0x1002fb30
void LegoBuildingManager::FUN_1002fb30()
{
	MxU32 i;

	for (i = 0; i < _countof(g_buildingInfo); i++) {
		g_buildingInfo[i].m_entity = NULL;
	}

	m_unk0x09 = 0;

	for (i = 0; i < m_numEntries; i++) {
		delete m_entries[i];
	}

	m_numEntries = 0;
}

// FUNCTION: LEGO1 0x1002fb80
// FUNCTION: BETA10 0x10063cae
MxResult LegoBuildingManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		LegoBuildingInfo* info = &g_buildingInfo[i];

		if (p_storage->Write(&info->m_cycle1, sizeof(info->m_cycle1)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_cycle2, sizeof(info->m_cycle2)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_cycle3, sizeof(info->m_cycle3)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_initialUnk0x11, sizeof(info->m_initialUnk0x11)) != SUCCESS) {
			goto done;
		}
	}

	if (p_storage->Write(&m_nextVariant, sizeof(m_nextVariant)) != SUCCESS) {
		goto done;
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x1002fc10
// FUNCTION: BETA10 0x10063dde
MxResult LegoBuildingManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		LegoBuildingInfo* info = &g_buildingInfo[i];

		if (p_storage->Read(&info->m_cycle1, sizeof(info->m_cycle1)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_cycle2, sizeof(info->m_cycle2)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_cycle3, sizeof(info->m_cycle3)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_unk0x11, sizeof(info->m_unk0x11)) != SUCCESS) {
			goto done;
		}

		info->m_initialUnk0x11 = info->m_unk0x11;
		AdjustHeight(i);
	}

	if (p_storage->Read(&m_nextVariant, sizeof(m_nextVariant)) != SUCCESS) {
		goto done;
	}

	if (g_buildingManagerConfig <= 1) {
		m_nextVariant = 0;
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x1002fcc0
// FUNCTION: BETA10 0x10063f1a
void LegoBuildingManager::AdjustHeight(MxS32 p_index)
{
	if (g_buildingInfo[p_index].m_unk0x11 > 0) {
		float value = g_buildingInfoDownshift[p_index] - g_buildingInfo[p_index].m_unk0x11;
		g_buildingInfo[p_index].m_unk0x014 =
			g_buildingInfoInit[p_index].m_unk0x014 - value * g_buildingInfoDownshiftScale[p_index];
	}
	else if (g_buildingInfo[p_index].m_unk0x11 == 0) {
		float value = g_buildingInfoDownshift[p_index] - g_buildingInfo[p_index].m_unk0x11;
		g_buildingInfo[p_index].m_unk0x014 =
			g_buildingInfoInit[p_index].m_unk0x014 - value * g_buildingInfoDownshiftScale[p_index];

		if (g_buildingInfo[p_index].m_entity != NULL) {
			LegoROI* roi = g_buildingInfo[p_index].m_entity->GetROI();
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}
		}
	}
	else {
		g_buildingInfo[p_index].m_unk0x014 = g_buildingInfoInit[p_index].m_unk0x014;
	}
}

// FUNCTION: LEGO1 0x1002fd70
// FUNCTION: BETA10 0x10063fc9
LegoBuildingInfo* LegoBuildingManager::GetInfo(LegoEntity* p_entity)
{
	MxS32 i;

	for (i = 0; i < _countof(g_buildingInfo); i++) {
		if (g_buildingInfo[i].m_entity == p_entity) {
			break;
		}
	}

	if (i < _countof(g_buildingInfo)) {
		return &g_buildingInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1002fdb0
// FUNCTION: BETA10 0x10064101
MxBool LegoBuildingManager::IncrementVariant(LegoEntity* p_entity)
{
	if (g_buildingManagerConfig <= 1) {
		return TRUE;
	}

	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_bit1 && info->m_unk0x11 == -1) {
		LegoROI* roi = p_entity->GetROI();
		if (++m_nextVariant >= _countof(g_buildingInfoHausName)) {
			m_nextVariant = 0;
		}

		roi->SetVisibility(FALSE);
		info->m_hausName = g_buildingInfoHausName[m_nextVariant];
		UpdatePosition(12, CurrentWorld());

		if (info->m_entity != NULL) {
			info->m_entity->GetROI()->SetVisibility(TRUE);
		}

		return TRUE;
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1002fe40
// FUNCTION: BETA10 0x100641d3
MxBool LegoBuildingManager::FUN_1002fe40(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_bit2) {
		info->m_cycle1++;

		if (info->m_cycle1 >= g_buildingCycle1Length) {
			info->m_cycle1 = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002fe80
// FUNCTION: BETA10 0x10064242
MxBool LegoBuildingManager::FUN_1002fe80(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_bit3) {
		info->m_cycle2++;

		if (info->m_cycle2 >= g_buildingCycle2Length[info - g_buildingInfo]) {
			info->m_cycle2 = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002fed0
// FUNCTION: BETA10 0x100642c2
MxBool LegoBuildingManager::FUN_1002fed0(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_bit4) {
		info->m_cycle3++;

		if (info->m_cycle3 > 3) {
			info->m_cycle3 = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002ff00
// FUNCTION: BETA10 0x1006432d
MxU32 LegoBuildingManager::GetBuildingEntityId(LegoEntity* p_entity)
{
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_bit3) {
		return g_buildingEntityId[info - g_buildingInfo] + info->m_cycle2;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002ff40
// FUNCTION: BETA10 0x10064398
MxU32 LegoBuildingManager::FUN_1002ff40(LegoEntity* p_entity, MxBool p_state)
{
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info == NULL || !(info->m_flags & LegoBuildingInfo::c_bit2)) {
		return 0;
	}

	if (p_state) {
		return info->m_cycle3 + g_cycleLengthOffset3;
	}

	if (info != NULL) {
		return info->m_cycle1 + g_cycleLengthOffset1;
	}

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
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info == NULL) {
		return FALSE;
	}

	return FUN_10030030(info - g_buildingInfo);
}

// STUB: LEGO1 0x10030030
MxBool LegoBuildingManager::FUN_10030030(MxS32 p_index)
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10030110
MxBool LegoBuildingManager::FUN_10030110(LegoBuildingInfo* p_data)
{
	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		if (&g_buildingInfo[i] == p_data) {
			return FUN_10030030(i);
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10030150
void LegoBuildingManager::ScheduleAnimation(LegoEntity* p_entity, MxU32 p_length, MxBool p_haveSound, MxBool p_unk0x28)
{
	m_world = CurrentWorld();

	if (p_haveSound) {
		m_sound = SoundManager()->GetCacheSoundManager()->FUN_1003d170("bcrash");
		m_sound->FUN_10006cb0(35, 60);
	}

	if (m_numEntries == 0) {
		m_unk0x28 = p_unk0x28;
		TickleManager()->RegisterClient(this, 50);
	}

	AnimEntry* entry = m_entries[m_numEntries] = new AnimEntry;
	m_numEntries++;

	entry->m_entity = p_entity;
	entry->m_roi = p_entity->GetROI();
	entry->m_time = Timer()->GetTime() + p_length + 1000;
	entry->m_unk0x0c = entry->m_roi->GetLocal2World()[3][1];
	entry->m_muted = p_haveSound == FALSE;
	FUN_100307b0(p_entity, -2);
}

// STUB: LEGO1 0x10030220
MxResult LegoBuildingManager::Tickle()
{
	// WIP, included some of this to understand the AnimEntry array.
	LegoTime time = Timer()->GetTime();

	if (m_numEntries != 0) {
		if (m_numEntries > 0) {
			for (MxS32 i = 0; i < m_numEntries; i++) {
				AnimEntry* entry = m_entries[i];
				if (entry->m_time <= time) {
					// Code to animate and play sounds
				}
			}
		}
	}
	else {
		TickleManager()->UnregisterClient(this);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10030590
// FUNCTION: BETA10 0x1006474c
void LegoBuildingManager::FUN_10030590()
{
	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		g_buildingInfo[i].m_unk0x11 = -1;
		g_buildingInfo[i].m_initialUnk0x11 = -1;
		AdjustHeight(i);

		if (g_buildingInfo[i].m_entity != NULL) {
			LegoROI* roi = g_buildingInfo[i].m_entity->GetROI();
			MxMatrix mat = roi->GetLocal2World();
			mat[3][1] = g_buildingInfo[i].m_unk0x014;
			roi->FUN_100a46b0(mat);
			VideoManager()->Get3DManager()->Moved(*roi);
		}
	}
}

// FUNCTION: LEGO1 0x10030630
MxResult LegoBuildingManager::FUN_10030630()
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10030790
LegoBuildingInfo* LegoBuildingManager::GetInfoArray(MxS32& p_length)
{
	if (m_unk0x09 == 0) {
		FUN_10030630();
	}

	p_length = _countof(g_buildingInfo);
	return g_buildingInfo;
}

// FUNCTION: LEGO1 0x100307b0
void LegoBuildingManager::FUN_100307b0(LegoEntity* p_entity, MxS32 p_adjust)
{
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		if (info->m_unk0x11 < 0) {
			info->m_unk0x11 = g_buildingInfoDownshift[info - g_buildingInfo];
		}

		if (info->m_unk0x11 > 0) {
			info->m_unk0x11 += p_adjust;
			if (info->m_unk0x11 <= 1 && p_adjust < 0) {
				info->m_unk0x11 = 0;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10030800
void LegoBuildingManager::FUN_10030800()
{
	for (MxS32 i = 0; i < _countof(g_buildingInfo); i++) {
		g_buildingInfo[i].m_initialUnk0x11 = g_buildingInfo[i].m_unk0x11;
	}
}
