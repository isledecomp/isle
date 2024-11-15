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
const char* g_buildingInfoVariants[5] = {
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
MxU32 LegoBuildingManager::g_maxSound = 6;

// GLOBAL: LEGO1 0x100f373c
MxU32 g_unk0x100f373c = 0x3c;

// GLOBAL: LEGO1 0x100f3740
MxU32 g_unk0x100f3740 = 0x42;

// clang-format off
// GLOBAL: LEGO1 0x100f3788
MxU32 g_buildingAnimationId[16] = {
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
MxS32 LegoBuildingManager::g_maxMove[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0};

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
	delete[] g_customizeAnimFile;
}

// FUNCTION: LEGO1 0x1002f9d0
void LegoBuildingManager::Init()
{
	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
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
void LegoBuildingManager::LoadWorldInfo()
{
	MxS32 i;
	LegoWorld* world = CurrentWorld();

	for (i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		CreateBuilding(i, world);
	}

	if (g_buildingManagerConfig <= 1) {
		LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingInfoVariants[0]);
		if (entity) {
			entity->GetROI()->SetVisibility(TRUE);
			m_unk0x09 = 0;
		}
	}
	else {
		for (i = 0; i < sizeOfArray(g_buildingInfoVariants); i++) {
			LegoEntity* entity = (LegoEntity*) world->Find("MxEntity", g_buildingInfoVariants[i]);
			if (entity) {
				entity->GetROI()->SetVisibility(m_nextVariant == i);
			}
		}
	}

	m_unk0x09 = 0;
}

// FUNCTION: LEGO1 0x1002fa90
// FUNCTION: BETA10 0x10063b88
void LegoBuildingManager::CreateBuilding(MxS32 p_index, LegoWorld* p_world)
{
	LegoEntity* entity = (LegoEntity*) p_world->Find("MxEntity", g_buildingInfo[p_index].m_variant);

	if (entity) {
		entity->SetType(LegoEntity::e_building);
		g_buildingInfo[p_index].m_entity = entity;
		LegoROI* roi = entity->GetROI();
		AdjustHeight(p_index);
		MxMatrix mat = roi->GetLocal2World();
		mat[3][1] = g_buildingInfo[p_index].m_unk0x014;
		roi->UpdateTransformationRelativeToParent(mat);
		VideoManager()->Get3DManager()->Moved(*roi);
	}
}

// FUNCTION: LEGO1 0x1002fb30
void LegoBuildingManager::Reset()
{
	MxU32 i;

	for (i = 0; i < sizeOfArray(g_buildingInfo); i++) {
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

	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		LegoBuildingInfo* info = &g_buildingInfo[i];

		if (p_storage->Write(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
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

	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		LegoBuildingInfo* info = &g_buildingInfo[i];

		if (p_storage->Read(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
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

	for (i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		if (g_buildingInfo[i].m_entity == p_entity) {
			break;
		}
	}

	if (i < sizeOfArray(g_buildingInfo)) {
		return &g_buildingInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1002fdb0
// FUNCTION: BETA10 0x10064101
MxBool LegoBuildingManager::SwitchVariant(LegoEntity* p_entity)
{
	if (g_buildingManagerConfig <= 1) {
		return TRUE;
	}

	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_hasVariants && info->m_unk0x11 == -1) {
		LegoROI* roi = p_entity->GetROI();
		if (++m_nextVariant >= sizeOfArray(g_buildingInfoVariants)) {
			m_nextVariant = 0;
		}

		roi->SetVisibility(FALSE);
		info->m_variant = g_buildingInfoVariants[m_nextVariant];
		CreateBuilding(12, CurrentWorld());

		if (info->m_entity != NULL) {
			info->m_entity->GetROI()->SetVisibility(TRUE);
		}

		return TRUE;
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1002fe40
// FUNCTION: BETA10 0x100641d3
MxBool LegoBuildingManager::SwitchSound(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_hasSounds) {
		info->m_sound++;

		if (info->m_sound >= g_maxSound) {
			info->m_sound = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002fe80
// FUNCTION: BETA10 0x10064242
MxBool LegoBuildingManager::SwitchMove(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_hasMoves) {
		info->m_move++;

		if (info->m_move >= g_maxMove[info - g_buildingInfo]) {
			info->m_move = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002fed0
// FUNCTION: BETA10 0x100642c2
MxBool LegoBuildingManager::SwitchMood(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_hasMoods) {
		info->m_mood++;

		if (info->m_mood > 3) {
			info->m_mood = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1002ff00
// FUNCTION: BETA10 0x1006432d
MxU32 LegoBuildingManager::GetAnimationId(LegoEntity* p_entity)
{
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info != NULL && info->m_flags & LegoBuildingInfo::c_hasMoves) {
		return g_buildingAnimationId[info - g_buildingInfo] + info->m_move;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002ff40
// FUNCTION: BETA10 0x10064398
MxU32 LegoBuildingManager::GetSoundId(LegoEntity* p_entity, MxBool p_state)
{
	LegoBuildingInfo* info = GetInfo(p_entity);

	if (info == NULL || !(info->m_flags & LegoBuildingInfo::c_hasSounds)) {
		return 0;
	}

	if (p_state) {
		return info->m_mood + g_unk0x100f3740;
	}

	if (info != NULL) {
		return info->m_sound + g_unk0x100f373c;
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

inline LegoBuildingInfo* GetBuildingInfo(MxS32 p_index)
{
	if (p_index >= sizeOfArray(g_buildingInfo)) {
		return NULL;
	}

	return &g_buildingInfo[p_index];
}

// FUNCTION: LEGO1 0x10030030
MxBool LegoBuildingManager::FUN_10030030(MxS32 p_index)
{
	if (p_index >= sizeOfArray(g_buildingInfo)) {
		return FALSE;
	}

	LegoBuildingInfo* info = GetBuildingInfo(p_index);
	if (!info) {
		return FALSE;
	}

	MxBool result = TRUE;

	if (info->m_unk0x11 < 0) {
		info->m_unk0x11 = g_buildingInfoDownshift[p_index];
	}

	if (info->m_unk0x11 <= 0) {
		result = FALSE;
	}
	else {
		LegoROI* roi = info->m_entity->GetROI();

		info->m_unk0x11 -= 2;
		if (info->m_unk0x11 == 1) {
			info->m_unk0x11 = 0;
			roi->SetVisibility(FALSE);
		}
		else {
			AdjustHeight(p_index);
			MxMatrix mat = roi->GetLocal2World();
			mat[3][1] = g_buildingInfo[p_index].m_unk0x014;
			roi->UpdateTransformationRelativeToParent(mat);
			VideoManager()->Get3DManager()->Moved(*roi);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10030110
MxBool LegoBuildingManager::FUN_10030110(LegoBuildingInfo* p_data)
{
	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		if (&g_buildingInfo[i] == p_data) {
			return FUN_10030030(i);
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10030150
void LegoBuildingManager::ScheduleAnimation(LegoEntity* p_entity, MxLong p_length, MxBool p_haveSound, MxBool p_unk0x28)
{
	m_world = CurrentWorld();

	if (p_haveSound) {
		m_sound = SoundManager()->GetCacheSoundManager()->FindSoundByKey("bcrash");
		m_sound->SetDistance(35, 60);
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
	entry->m_unk0x0c = entry->m_roi->GetWorldPosition()[1];
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
	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		g_buildingInfo[i].m_unk0x11 = -1;
		g_buildingInfo[i].m_initialUnk0x11 = -1;
		AdjustHeight(i);

		if (g_buildingInfo[i].m_entity != NULL) {
			LegoROI* roi = g_buildingInfo[i].m_entity->GetROI();
			MxMatrix mat = roi->GetLocal2World();
			mat[3][1] = g_buildingInfo[i].m_unk0x014;
			roi->UpdateTransformationRelativeToParent(mat);
			VideoManager()->Get3DManager()->Moved(*roi);
		}
	}
}

// STUB: LEGO1 0x10030630
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

	p_length = sizeOfArray(g_buildingInfo);
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
	for (MxS32 i = 0; i < sizeOfArray(g_buildingInfo); i++) {
		g_buildingInfo[i].m_initialUnk0x11 = g_buildingInfo[i].m_unk0x11;
	}
}
