#include "legoanimationmanager.h"

#include "anim/legoanim.h"
#include "animstate.h"
#include "define.h"
#include "islepathactor.h"
#include "legoanimmmpresenter.h"
#include "legoanimpresenter.h"
#include "legocharactermanager.h"
#include "legoendanimnotificationparam.h"
#include "legoextraactor.h"
#include "legogamestate.h"
#include "legomain.h"
#include "legoroilist.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "viewmanager/viewmanager.h"

#include <io.h>

DECOMP_SIZE_ASSERT(LegoAnimationManager, 0x500)
DECOMP_SIZE_ASSERT(Character, 0x18)
DECOMP_SIZE_ASSERT(Vehicle, 0x08)
DECOMP_SIZE_ASSERT(Unknown0x3c, 0x18)
DECOMP_SIZE_ASSERT(LegoTranInfo, 0x78)

// GLOBAL: LEGO1 0x100d8b28
MxU8 g_unk0x100d8b28[] = {0, 1, 2, 4, 8, 16};

// GLOBAL: LEGO1 0x100f6d20
Vehicle g_vehicles[] = {
	{"bikebd", 0, FALSE},
	{"bikepg", 0, FALSE},
	{"bikerd", 0, FALSE},
	{"bikesy", 0, FALSE},
	{"motoni", 0, FALSE},
	{"motola", 0, FALSE},
	{"board", 0, FALSE}
};

// GLOBAL: LEGO1 0x100f7048
Character g_characters[47] = {
	{"pepper", FALSE, 6, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 50, 1},
	{"mama", FALSE, -1, 0, FALSE, FALSE, FALSE, 1500, 20000, FALSE, 0, 2},
	{"papa", FALSE, -1, 0, FALSE, FALSE, FALSE, 1500, 20000, FALSE, 0, 3},
	{"nick", FALSE, 4, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 20, 4},
	{"laura", FALSE, 5, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 20, 5},
	{"brickstr", FALSE, -1, 0, FALSE, FALSE, FALSE, 1000, 20000, FALSE, 0, 6},
	{"studs", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"rhoda", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"valerie", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"snap", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"pt", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"mg", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"bu", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"ml", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"nu", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"na", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"cl", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"en", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"re", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"ro", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"d1", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"d2", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"d3", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"d4", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l1", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l2", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l3", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l4", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l5", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"l6", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"b1", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"b2", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"b3", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"b4", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"cm", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"gd", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"rd", FALSE, 2, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 50, 9},
	{"pg", FALSE, 1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 50, 8},
	{"bd", FALSE, 0, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 100, 7},
	{"sy", FALSE, 3, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 100, 10},
	{"gn", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"df", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"bs", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"lt", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"st", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"bm", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0},
	{"jk", FALSE, -1, 0, FALSE, FALSE, TRUE, 1500, 20000, FALSE, 0, 0}
};

// GLOBAL: LEGO1 0x100f74b0
float g_unk0x100f74b0[6][3] = {
	{10.0f, -1.0f, 1.0f},
	{7.0f, 144.0f, 100.0f},
	{5.0f, 100.0f, 36.0f},
	{3.0f, 36.0f, 25.0f},
	{1.0f, 25.0f, 16.0f},
	{-1.0f, 16.0f, 2.0f}
};

// GLOBAL: LEGO1 0x100f74f8
MxS32 g_legoAnimationManagerConfig = 1;

// GLOBAL: LEGO1 0x100f7500
float g_unk0x100f7500 = 0.1f;

// FUNCTION: LEGO1 0x1005eb50
void LegoAnimationManager::configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig)
{
	g_legoAnimationManagerConfig = p_legoAnimationManagerConfig;
}

// FUNCTION: LEGO1 0x1005eb60
// FUNCTION: BETA10 0x1003f940
LegoAnimationManager::LegoAnimationManager()
{
	m_unk0x1c = 0;
	m_animState = NULL;
	m_unk0x424 = NULL;

	Init();

	NotificationManager()->Register(this);
	TickleManager()->RegisterClient(this, 10);
}

// FUNCTION: LEGO1 0x1005ed30
// FUNCTION: BETA10 0x1003fa27
LegoAnimationManager::~LegoAnimationManager()
{
	TickleManager()->UnregisterClient(this);

	FUN_10061010(FALSE);

	for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
		LegoROI* roi = m_unk0x3c[i].m_roi;

		if (roi != NULL) {
			LegoPathActor* actor = CharacterManager()->GetActor(roi->GetName());

			if (actor != NULL && actor->GetController() != NULL && CurrentWorld() != NULL) {
				CurrentWorld()->FUN_1001fc80((IslePathActor*) actor);
				actor->ClearController();
			}

			CharacterManager()->FUN_10083db0(roi);
		}
	}

	if (m_tranInfoList != NULL) {
		delete m_tranInfoList;
	}

	if (m_tranInfoList2 != NULL) {
		delete m_tranInfoList2;
	}

	DeleteAnimations();

	if (m_unk0x424 != NULL) {
		FUN_10063aa0();
		delete m_unk0x424;
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1005ee80
// FUNCTION: BETA10 0x1003fbc0
void LegoAnimationManager::Reset(MxBool p_und)
{
	m_unk0x402 = FALSE;

	if (p_und && m_animState != NULL) {
		m_animState->SetFlag();
	}

	MxBool suspended = m_suspended;
	Suspend();

	if (m_tranInfoList != NULL) {
		delete m_tranInfoList;
	}

	if (m_tranInfoList2 != NULL) {
		delete m_tranInfoList2;
	}

	DeleteAnimations();
	Init();

	m_suspended = suspended;
	m_unk0x428 = m_unk0x3a;
	m_unk0x429 = m_unk0x400;
	m_unk0x42a = m_unk0x402;
}

// FUNCTION: LEGO1 0x1005ef10
// FUNCTION: BETA10 0x1003fc7a
void LegoAnimationManager::Suspend()
{
	m_animState = (AnimState*) GameState()->GetState("AnimState");
	if (m_animState == NULL) {
		m_animState = (AnimState*) GameState()->CreateState("AnimState");
	}

	if (m_scriptIndex == 0) {
		m_animState->FUN_10065240(m_animCount, m_anims, m_unk0x3fc);
	}

	if (!m_suspended) {
		m_suspended = TRUE;
		m_unk0x428 = m_unk0x3a;
		m_unk0x429 = m_unk0x400;
		m_unk0x42a = m_unk0x402;
		m_unk0x402 = FALSE;

		FUN_10061010(FALSE);

		MxS32 i;
		for (i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
			LegoROI* roi = m_unk0x3c[i].m_roi;

			if (roi != NULL) {
				LegoPathActor* actor = CharacterManager()->GetActor(roi->GetName());

				if (actor != NULL && actor->GetController() != NULL) {
					actor->GetController()->FUN_10046770(actor);
					actor->ClearController();
				}

				CharacterManager()->FUN_10083db0(roi);
			}

			if (m_unk0x3c[i].m_unk0x14) {
				m_unk0x3c[i].m_unk0x14 = FALSE;

				MxS32 vehicleId = g_characters[m_unk0x3c[i].m_characterId].m_vehicleId;
				if (vehicleId >= 0) {
					g_vehicles[vehicleId].m_unk0x05 = FALSE;

					LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
					if (roi != NULL) {
						roi->SetVisibility(FALSE);
					}
				}
			}

			m_unk0x3c[i].m_roi = NULL;
			m_unk0x3c[i].m_characterId = -1;
			m_unk0x3c[i].m_unk0x10 = -1.0f;
		}

		m_unk0x18 = 0;
		m_unk0x1a = FALSE;
		m_unk0x3a = FALSE;
		m_unk0x400 = FALSE;
		m_unk0x414 = 0;
		m_unk0x401 = FALSE;

		for (i = 0; i < (MxS32) _countof(g_characters); i++) {
			g_characters[i].m_unk0x04 = FALSE;
		}
	}
}

// FUNCTION: LEGO1 0x1005f0b0
// FUNCTION: BETA10 0x1003fefe
void LegoAnimationManager::Resume()
{
	if (m_suspended) {
		m_unk0x408 = m_unk0x40c = m_unk0x404 = Timer()->GetTime();
		m_unk0x410 = 5000;
		m_unk0x3a = m_unk0x428;
		m_unk0x400 = m_unk0x429;
		m_unk0x402 = m_unk0x42a;
		m_suspended = FALSE;
	}
}

// FUNCTION: LEGO1 0x1005f130
// FUNCTION: BETA10 0x1003ffb7
void LegoAnimationManager::Init()
{
	m_unk0x402 = FALSE;
	m_scriptIndex = -1;
	m_animCount = 0;
	m_anims = NULL;
	m_unk0x18 = 0;
	m_unk0x1a = FALSE;
	m_tranInfoList = NULL;
	m_tranInfoList2 = NULL;
	m_unk0x41c = g_legoAnimationManagerConfig <= 1 ? 10 : 20;

	MxS32 i;
	for (i = 0; i < (MxS32) _countof(m_unk0x28); i++) {
		m_unk0x28[i] = NULL;
		m_unk0x30[i] = 0;
	}

	for (i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
		m_unk0x3c[i].m_roi = NULL;
		m_unk0x3c[i].m_characterId = -1;
		m_unk0x3c[i].m_unk0x10 = -1.0f;
		m_unk0x3c[i].m_unk0x14 = FALSE;
	}

	m_unk0x38 = FALSE;
	m_unk0x39 = FALSE;
	m_unk0x3a = TRUE;
	m_unk0x3fc = 0;
	m_unk0x400 = FALSE;
	m_unk0x414 = 0;
	m_numAllowedExtras = 5;
	m_unk0x0e = 0;
	m_unk0x10 = 0;
	m_unk0x401 = FALSE;
	m_suspended = FALSE;
	m_unk0x430 = FALSE;
	m_unk0x42c = NULL;
	m_unk0x408 = m_unk0x40c = m_unk0x404 = Timer()->GetTime();
	m_unk0x410 = 5000;

	for (i = 0; i < (MxS32) _countof(g_characters); i++) {
		g_characters[i].m_active = FALSE;
		g_characters[i].m_unk0x04 = FALSE;
	}

	for (i = 0; i < (MxS32) _countof(g_vehicles); i++) {
		g_vehicles[i].m_unk0x04 = 0;
		g_vehicles[i].m_unk0x05 = FALSE;
	}

	if (m_unk0x424 != NULL) {
		FUN_10063aa0();
		delete m_unk0x424;
	}

	m_unk0x424 = new LegoROIList();
}

// FUNCTION: LEGO1 0x1005f6d0
// FUNCTION: BETA10 0x100401e7
void LegoAnimationManager::FUN_1005f6d0(MxBool p_unk0x400)
{
	if (m_suspended) {
		m_unk0x429 = p_unk0x400;
	}
	else {
		m_unk0x400 = p_unk0x400;

		if (!p_unk0x400) {
			FUN_100627d0(TRUE);
		}
	}
}

// FUNCTION: LEGO1 0x1005f700
// FUNCTION: BETA10 0x1004024c
void LegoAnimationManager::FUN_1005f700(MxBool p_unk0x3a)
{
	if (m_suspended) {
		m_unk0x428 = p_unk0x3a;
	}
	else {
		m_unk0x3a = p_unk0x3a;
	}
}

// FUNCTION: LEGO1 0x1005f720
MxResult LegoAnimationManager::LoadScriptInfo(MxS32 p_scriptIndex)
{
	MxResult result = FAILURE;
	MxS32 i, j, k;

	if (m_scriptIndex != p_scriptIndex) {
		if (m_tranInfoList != NULL) {
			delete m_tranInfoList;
			m_tranInfoList = NULL;
		}

		if (m_tranInfoList2 != NULL) {
			delete m_tranInfoList2;
			m_tranInfoList2 = NULL;
		}

		for (i = 0; i < (MxS32) _countof(m_unk0x28); i++) {
			m_unk0x28[i] = NULL;
			m_unk0x30[i] = 0;
		}

		m_unk0x38 = FALSE;
		m_unk0x39 = FALSE;
		m_unk0x430 = FALSE;
		m_unk0x42c = NULL;

		for (j = 0; j < (MxS32) _countof(g_characters); j++) {
			g_characters[j].m_active = FALSE;
		}

		m_animState = (AnimState*) GameState()->GetState("AnimState");
		if (m_animState == NULL) {
			m_animState = (AnimState*) GameState()->CreateState("AnimState");
		}

		if (m_scriptIndex == 0) {
			m_animState->FUN_10065240(m_animCount, m_anims, m_unk0x3fc);
		}

		DeleteAnimations();

		LegoFile file;

		if (p_scriptIndex == -1) {
			result = SUCCESS;
			goto done;
		}

		char filename[128];
		char path[1024];
		sprintf(filename, "lego\\data\\%sinf.dta", Lego()->GetScriptName(p_scriptIndex));
		sprintf(path, "%s", MxOmni::GetHD());

		if (path[strlen(path) - 1] != '\\') {
			strcat(path, "\\");
		}

		strcat(path, filename);

		if (_access(path, 4)) {
			sprintf(path, "%s", MxOmni::GetCD());

			if (path[strlen(path) - 1] != '\\') {
				strcat(path, "\\");
			}

			strcat(path, filename);

			if (_access(path, 4)) {
				goto done;
			}
		}

		if (file.Open(path, LegoFile::c_read) == FAILURE) {
			goto done;
		}

		MxU32 version;
		if (file.Read(&version, sizeof(version)) == FAILURE) {
			goto done;
		}

		if (version != 3) {
			OmniError("World animation version mismatch", 0);
			goto done;
		}

		if (file.Read(&m_animCount, sizeof(m_animCount)) == FAILURE) {
			goto done;
		}

		m_anims = new AnimInfo[m_animCount];
		memset(m_anims, 0, m_animCount * sizeof(*m_anims));

		for (j = 0; j < m_animCount; j++) {
			if (ReadAnimInfo(&file, &m_anims[j]) == FAILURE) {
				goto done;
			}

			m_anims[j].m_unk0x28 = GetCharacterIndex(m_anims[j].m_name + strlen(m_anims[j].m_name) - 2);
			m_anims[j].m_unk0x29 = FALSE;

			for (k = 0; k < 3; k++) {
				m_anims[j].m_unk0x2a[k] = -1;
			}

			if (m_anims[j].m_unk0x08 == -1) {
				for (MxS32 l = 0; l < m_anims[j].m_modelCount; l++) {
					MxS32 index = GetCharacterIndex(m_anims[j].m_models[l].m_name);

					if (index >= 0) {
						g_characters[index].m_active = TRUE;
					}
				}
			}

			MxS32 count = 0;
			for (MxS32 m = 0; m < m_anims[j].m_modelCount; m++) {
				MxU32 n;

				if (FindVehicle(m_anims[j].m_models[m].m_name, n) && m_anims[j].m_models[m].m_unk0x2c) {
					m_anims[j].m_unk0x2a[count++] = n;
					if (count > 3) {
						break;
					}
				}
			}
		}

		m_scriptIndex = p_scriptIndex;
		m_tranInfoList = new LegoTranInfoList();
		m_tranInfoList2 = new LegoTranInfoList();

		FUN_100617c0(-1, m_unk0x0e, m_unk0x10);

		result = SUCCESS;
		m_unk0x402 = TRUE;

		if (m_suspended) {
			m_unk0x428 = m_unk0x3a;
			m_unk0x429 = m_unk0x400;
			m_unk0x42a = TRUE;
			m_unk0x3a = FALSE;
			m_unk0x400 = FALSE;
			m_unk0x402 = FALSE;
		}

		if (p_scriptIndex == 0) {
			m_animState->FUN_100651d0(m_animCount, m_anims, m_unk0x3fc);
		}
	}

done:
	if (result == FAILURE) {
		DeleteAnimations();
	}

	return result;
}

// FUNCTION: LEGO1 0x10060140
MxBool LegoAnimationManager::FindVehicle(const char* p_name, MxU32& p_index)
{
	for (MxS32 i = 0; i < _countof(g_vehicles); i++) {
		if (!strcmpi(p_name, g_vehicles[i].m_name)) {
			p_index = i;
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10060180
MxResult LegoAnimationManager::ReadAnimInfo(LegoFile* p_file, AnimInfo* p_info)
{
	MxResult result = FAILURE;
	MxU8 length;
	MxS32 i, j;

	if (p_file->Read(&length, sizeof(length)) == FAILURE) {
		goto done;
	}

	p_info->m_name = new char[length + 1];
	if (p_file->Read(p_info->m_name, length) == FAILURE) {
		goto done;
	}

	p_info->m_name[length] = 0;
	if (p_file->Read(&p_info->m_objectId, sizeof(p_info->m_objectId)) == FAILURE) {
		goto done;
	}

	if (p_file->Read(&p_info->m_unk0x08, sizeof(p_info->m_unk0x08)) == FAILURE) {
		goto done;
	}
	if (p_file->Read(&p_info->m_unk0x0a, sizeof(p_info->m_unk0x0a)) == FAILURE) {
		goto done;
	}
	if (p_file->Read(&p_info->m_unk0x0b, sizeof(p_info->m_unk0x0b)) == FAILURE) {
		goto done;
	}
	if (p_file->Read(&p_info->m_unk0x0c, sizeof(p_info->m_unk0x0c)) == FAILURE) {
		goto done;
	}
	if (p_file->Read(&p_info->m_unk0x0d, sizeof(p_info->m_unk0x0d)) == FAILURE) {
		goto done;
	}

	for (i = 0; i < (MxS32) _countof(p_info->m_unk0x10); i++) {
		if (p_file->Read(&p_info->m_unk0x10[i], sizeof(*p_info->m_unk0x10)) != SUCCESS) {
			goto done;
		}
	}

	if (p_file->Read(&p_info->m_modelCount, sizeof(p_info->m_modelCount)) == FAILURE) {
		goto done;
	}

	p_info->m_models = new ModelInfo[p_info->m_modelCount];
	memset(p_info->m_models, 0, p_info->m_modelCount * sizeof(*p_info->m_models));

	for (j = 0; j < p_info->m_modelCount; j++) {
		if (ReadModelInfo(p_file, &p_info->m_models[j]) == FAILURE) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x10060310
MxResult LegoAnimationManager::ReadModelInfo(LegoFile* p_file, ModelInfo* p_info)
{
	MxResult result = FAILURE;
	MxU8 length;

	if (p_file->Read(&length, 1) == FAILURE) {
		goto done;
	}

	p_info->m_name = new char[length + 1];
	if (p_file->Read(p_info->m_name, length) == FAILURE) {
		goto done;
	}

	p_info->m_name[length] = 0;
	if (p_file->Read(&p_info->m_unk0x04, sizeof(p_info->m_unk0x04)) == FAILURE) {
		goto done;
	}

	if (p_file->Read(p_info->m_location, sizeof(p_info->m_location)) != SUCCESS) {
		goto done;
	}
	if (p_file->Read(p_info->m_direction, sizeof(p_info->m_direction)) != SUCCESS) {
		goto done;
	}
	if (p_file->Read(p_info->m_up, sizeof(p_info->m_up)) != SUCCESS) {
		goto done;
	}
	if (p_file->Read(&p_info->m_unk0x2c, sizeof(p_info->m_unk0x2c)) == FAILURE) {
		goto done;
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100603c0
void LegoAnimationManager::DeleteAnimations()
{
	MxBool suspended = m_suspended;

	if (m_anims != NULL) {
		for (MxS32 i = 0; i < m_animCount; i++) {
			delete m_anims[i].m_name;

			if (m_anims[i].m_models != NULL) {
				for (MxS32 j = 0; j < m_anims[i].m_modelCount; j++) {
					delete m_anims[i].m_models[j].m_name;
				}

				delete m_anims[i].m_models;
			}
		}

		delete m_anims;
	}

	Init();
	m_suspended = suspended;
}

// FUNCTION: LEGO1 0x10060570
// FUNCTION: BETA10 0x10041463
void LegoAnimationManager::FUN_10060570(MxBool p_unk0x1a)
{
	m_unk0x39 = FALSE;
	m_unk0x430 = FALSE;
	m_unk0x42c = NULL;

	if (m_unk0x1a != p_unk0x1a && (m_unk0x1a = p_unk0x1a)) {
		do {
			if (FUN_100605e0(m_unk0x18, TRUE, NULL, TRUE, NULL, FALSE, TRUE, TRUE, TRUE) != FAILURE) {
				return;
			}

			m_unk0x18++;
		} while (m_unk0x18 < m_animCount);

		m_unk0x1a = FALSE;
		m_unk0x18 = 0;
	}
}

// FUNCTION: LEGO1 0x100605e0
// FUNCTION: BETA10 0x1004152b
MxResult LegoAnimationManager::FUN_100605e0(
	MxU32 p_index,
	MxBool p_unk0x0a,
	MxMatrix* p_matrix,
	MxBool p_bool1,
	LegoROI* p_roi,
	MxBool p_bool2,
	MxBool p_bool3,
	MxBool p_bool4,
	MxBool p_bool5
)
{
	MxResult result = FAILURE;

	if (m_scriptIndex != -1 && p_index < m_animCount && m_tranInfoList != NULL) {
		FUN_100627d0(FALSE);
		FUN_10062770();

		MxDSAction action;
		AnimInfo& animInfo = m_anims[p_index];

		if (!p_bool1) {
			if (m_unk0x39 || !animInfo.m_unk0x29) {
				return FAILURE;
			}

			if (FUN_100623a0(animInfo)) {
				return FAILURE;
			}

			if (FUN_10062710(animInfo)) {
				return FAILURE;
			}
		}

		FUN_10062580(animInfo);

		LegoTranInfo* tranInfo = new LegoTranInfo();
		tranInfo->m_animInfo = &animInfo;
		tranInfo->m_index = ++m_unk0x1c;
		tranInfo->m_unk0x10 = 0;
		tranInfo->m_unk0x08 = p_roi;
		tranInfo->m_unk0x12 = m_anims[p_index].m_unk0x08;
		tranInfo->m_unk0x14 = p_unk0x0a;
		tranInfo->m_objectId = animInfo.m_objectId;
		tranInfo->m_unk0x15 = p_bool2;

		if (p_matrix != NULL) {
			tranInfo->m_unk0x0c = new MxMatrix(*p_matrix);
		}

		tranInfo->m_unk0x1c = m_unk0x28;
		tranInfo->m_unk0x20 = m_unk0x30;
		tranInfo->m_unk0x28 = p_bool3;
		tranInfo->m_unk0x29 = p_bool4;

		if (m_tranInfoList != NULL) {
			m_tranInfoList->Append(tranInfo);
		}

		char buf[256];
		sprintf(buf, "%s:%d", g_strANIMMAN_ID, tranInfo->m_index);

		action.SetAtomId(*Lego()->GetScriptAtom(m_scriptIndex));
		action.SetObjectId(animInfo.m_objectId);
		action.SetUnknown24(-1);
		action.AppendExtra(strlen(buf) + 1, buf);

		if (StartActionIfUnknown0x13c(action) == SUCCESS) {
			BackgroundAudioManager()->LowerVolume();
			tranInfo->m_flags |= LegoTranInfo::c_bit2;
			animInfo.m_unk0x22++;
			m_unk0x404 = Timer()->GetTime();

			if (p_bool5) {
				FUN_100648f0(tranInfo, m_unk0x404);
			}
			else if (p_unk0x0a) {
				IslePathActor* actor = CurrentActor();

				if (actor != NULL) {
					actor->SetState(4);
					actor->SetWorldSpeed(0.0f);
				}
			}

			m_unk0x39 = TRUE;
			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100609f0
// FUNCTION: BETA10 0x10041a38
MxResult LegoAnimationManager::FUN_100609f0(MxU32 p_objectId, MxMatrix* p_matrix, MxBool p_und1, MxBool p_und2)
{
	MxResult result = FAILURE;
	MxDSAction action;

	FUN_100627d0(FALSE);

	LegoTranInfo* info = new LegoTranInfo();
	info->m_animInfo = NULL;
	info->m_index = ++m_unk0x1c;
	info->m_unk0x10 = 0;
	info->m_unk0x08 = NULL;
	info->m_unk0x12 = -1;
	info->m_unk0x14 = FALSE;
	info->m_objectId = p_objectId;

	if (p_matrix != NULL) {
		info->m_unk0x0c = new MxMatrix(*p_matrix);
	}

	FUN_10062770();

	info->m_unk0x1c = m_unk0x28;
	info->m_unk0x20 = m_unk0x30;
	info->m_unk0x28 = p_und1;
	info->m_unk0x29 = p_und2;

	if (m_tranInfoList != NULL) {
		m_tranInfoList->Append(info);
	}

	char buf[256];
	sprintf(buf, "%s:%d", g_strANIMMAN_ID, info->m_index);

	action.SetAtomId(*Lego()->GetScriptAtom(m_scriptIndex));
	action.SetObjectId(p_objectId);
	action.SetUnknown24(-1);
	action.AppendExtra(strlen(buf) + 1, buf);

	if (StartActionIfUnknown0x13c(action) == SUCCESS) {
		BackgroundAudioManager()->LowerVolume();
		info->m_flags |= LegoTranInfo::c_bit2;
		m_unk0x39 = TRUE;
		m_unk0x404 = Timer()->GetTime();
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10060d00
MxResult LegoAnimationManager::StartEntityAction(MxDSAction& p_dsAction, LegoEntity* p_entity)
{
	MxResult result = FAILURE;
	LegoROI* roi = p_entity->GetROI();

	if (p_entity->GetType() == LegoEntity::e_character) {
		LegoPathActor* actor = CharacterManager()->GetActor(roi->GetName());

		if (actor) {
			LegoPathController* controller = actor->GetController();

			if (controller) {
				controller->FUN_10046770(actor);
				actor->ClearController();

				for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
					if (m_unk0x3c[i].m_roi == roi) {
						MxS32 characterId = m_unk0x3c[i].m_characterId;
						g_characters[characterId].m_unk0x07 = TRUE;
						MxS32 vehicleId = g_characters[characterId].m_vehicleId;

						if (vehicleId >= 0) {
							g_vehicles[vehicleId].m_unk0x05 = FALSE;
						}
						break;
					}
				}
			}
		}
	}

	if (LegoOmni::GetInstance()->StartActionIfUnknown0x13c(p_dsAction) == SUCCESS) {
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10060dc0
// FUNCTION: BETA10 0x10041f2c
MxResult LegoAnimationManager::FUN_10060dc0(
	IsleScript::Script p_objectId,
	MxMatrix* p_matrix,
	MxBool p_param3,
	MxBool p_param4,
	LegoROI* p_roi,
	MxBool p_param6,
	MxBool p_param7,
	MxBool p_param8,
	MxBool p_param9
)
{
	MxResult result = FAILURE;
	MxBool found = FALSE;

	if (!Lego()->m_unk0x13c) {
		return SUCCESS;
	}

	for (MxS32 i = 0; i < m_animCount; i++) {
		if (m_anims[i].m_objectId == p_objectId) {
			found = TRUE;
			MxBool unk0x0a;

			switch (p_param4) {
			case FALSE:
				unk0x0a = m_anims[i].m_unk0x0a;
				break;
			case TRUE:
				unk0x0a = TRUE;
				break;
			default:
				unk0x0a = FALSE;
				break;
			}

			result = FUN_100605e0(i, unk0x0a, p_matrix, p_param3, p_roi, p_param6, p_param7, p_param8, p_param9);
			break;
		}
	}

	if (!found && p_param3 != FALSE) {
		result = FUN_100609f0(p_objectId, p_matrix, p_param7, p_param8);
	}

	return result;
}

// FUNCTION: LEGO1 0x10061010
// FUNCTION: BETA10 0x100422cc
void LegoAnimationManager::FUN_10061010(MxBool p_und)
{
	MxBool unk0x39 = FALSE;

	FUN_10064b50(-1);

	if (m_tranInfoList != NULL) {
		LegoTranInfoListCursor cursor(m_tranInfoList);
		LegoTranInfo* tranInfo;

		while (cursor.Next(tranInfo)) {
			if (tranInfo->m_presenter != NULL) {
				// TODO: Match
				MxU32 flags = tranInfo->m_flags;

				if (tranInfo->m_unk0x14 && tranInfo->m_unk0x12 != -1 && p_und) {
					LegoAnim* anim;

					if (tranInfo->m_presenter->GetPresenter() != NULL &&
						(anim = tranInfo->m_presenter->GetPresenter()->GetAnimation()) != NULL &&
						anim->GetScene() != NULL) {
						if (flags & LegoTranInfo::c_bit2) {
							BackgroundAudioManager()->RaiseVolume();
							tranInfo->m_flags &= ~LegoTranInfo::c_bit2;
						}

						tranInfo->m_presenter->FUN_1004b840();
						tranInfo->m_unk0x14 = FALSE;
					}
					else {
						tranInfo->m_presenter->FUN_1004b8c0();
						tranInfo->m_unk0x14 = FALSE;
						unk0x39 = TRUE;
					}
				}
				else {
					if (flags & LegoTranInfo::c_bit2) {
						BackgroundAudioManager()->RaiseVolume();
						tranInfo->m_flags &= ~LegoTranInfo::c_bit2;
					}

					tranInfo->m_presenter->FUN_1004b840();
				}
			}
			else {
				if (m_tranInfoList2 != NULL) {
					LegoTranInfoListCursor cursor(m_tranInfoList2);

					if (!cursor.Find(tranInfo)) {
						m_tranInfoList2->Append(tranInfo);
					}
				}

				unk0x39 = TRUE;
			}
		}
	}

	m_unk0x39 = unk0x39;
	m_unk0x404 = Timer()->GetTime();
}

// FUNCTION: LEGO1 0x10061530
void LegoAnimationManager::FUN_10061530()
{
	if (m_tranInfoList2 != NULL) {
		LegoTranInfoListCursor cursor(m_tranInfoList2);
		LegoTranInfo* tranInfo;

		while (cursor.Next(tranInfo)) {
			LegoTranInfoListCursor cursor2(m_tranInfoList);

			if (cursor2.Find(tranInfo)) {
				if (tranInfo->m_presenter != NULL) {
					if (tranInfo->m_flags & LegoTranInfo::c_bit2) {
						BackgroundAudioManager()->RaiseVolume();
						tranInfo->m_flags &= ~LegoTranInfo::c_bit2;
					}

					tranInfo->m_presenter->FUN_1004b840();
					cursor.Detach();
				}
			}
			else {
				cursor.Detach();
			}
		}
	}
}

// FUNCTION: LEGO1 0x100617c0
// FUNCTION: BETA10 0x1004240b
MxResult LegoAnimationManager::FUN_100617c0(MxS32 p_unk0x08, MxU16& p_unk0x0e, MxU16& p_unk0x10)
{
	MxResult result = FAILURE;
	MxU16 unk0x0e = 0;
	MxU16 unk0x10 = 0;
	MxBool success = FALSE;

	if (p_unk0x08 == -1) {
		MxS32 i;

		for (i = 0; i < m_animCount; i++) {
			if (m_anims[i].m_unk0x08 == p_unk0x08) {
				unk0x0e = i;
				success = TRUE;
				break;
			}
		}

		if (success) {
			for (; i < m_animCount && m_anims[i].m_unk0x08 == p_unk0x08; i++) {
				unk0x10 = i;
			}
		}
	}
	else {
		MxS32 i;

		for (i = 0; m_animCount > i && m_anims[i].m_unk0x08 != -1; i++) {
			if (m_anims[i].m_unk0x08 == p_unk0x08) {
				unk0x0e = i;
				success = TRUE;
				break;
			}
		}

		if (success) {
			for (; i < m_animCount && m_anims[i].m_unk0x08 == p_unk0x08; i++) {
				unk0x10 = i;
			}
		}
	}

	if (success) {
		p_unk0x0e = unk0x0e;
		p_unk0x10 = unk0x10;
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100618f0
// FUNCTION: BETA10 0x100425f0
LegoTranInfo* LegoAnimationManager::GetTranInfo(MxU32 p_index)
{
	if (m_tranInfoList != NULL) {
		LegoTranInfoListCursor cursor(m_tranInfoList);
		LegoTranInfo* tranInfo;

		while (cursor.Next(tranInfo)) {
			if (tranInfo->m_index == p_index) {
				return tranInfo;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100619f0
// FUNCTION: BETA10 0x100426b1
MxLong LegoAnimationManager::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetSender() == this) {
		if (((MxNotificationParam&) p_param).GetType() == c_notificationEndAnim) {
			FUN_100605e0(m_unk0x18, TRUE, NULL, TRUE, NULL, FALSE, TRUE, TRUE, TRUE);
		}
	}
	else if (((MxNotificationParam&) p_param).GetType() == c_notificationEndAnim && m_tranInfoList != NULL) {
		LegoTranInfoListCursor cursor(m_tranInfoList);
		LegoTranInfo* tranInfo;

		MxU32 index = ((LegoEndAnimNotificationParam&) p_param).GetIndex();
		MxBool found = FALSE;

		while (cursor.Next(tranInfo)) {
			if (tranInfo->m_index == index) {
				if (m_unk0x430 && m_unk0x42c == tranInfo) {
					FUN_10064b50(-1);
				}

				if (tranInfo->m_flags & LegoTranInfo::c_bit2) {
					BackgroundAudioManager()->RaiseVolume();
				}

				m_unk0x39 = FALSE;
				m_unk0x404 = Timer()->GetTime();

				found = TRUE;
				cursor.Detach();
				delete tranInfo;

				for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
					LegoROI* roi = m_unk0x3c[i].m_roi;

					if (roi != NULL) {
						LegoExtraActor* actor = CharacterManager()->GetActor(roi->GetName());

						if (actor != NULL) {
							actor->Restart();
						}
					}
				}

				break;
			}
		}

		if (m_unk0x1a && found) {
			m_unk0x18++;

			if (m_animCount <= m_unk0x18) {
				m_unk0x1a = FALSE;
			}
			else {
				LegoEndAnimNotificationParam param(c_notificationEndAnim, this, 0);
				NotificationManager()->Send(this, param);
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10061cc0
// FUNCTION: BETA10 0x1004293c
MxResult LegoAnimationManager::Tickle()
{
	FUN_10061530();

	if (!m_unk0x402) {
		return SUCCESS;
	}

	IslePathActor* actor = CurrentActor();
	LegoROI* roi;

	if (actor == NULL || (roi = actor->GetROI()) == NULL) {
		return SUCCESS;
	}

	if (m_unk0x401) {
		for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
			LegoROI* roi = m_unk0x3c[i].m_roi;

			if (roi != NULL && m_unk0x3c[i].m_unk0x0d) {
				LegoPathActor* actor = CharacterManager()->GetActor(roi->GetName());

				if (actor != NULL && actor->GetController() != NULL) {
					actor->GetController()->FUN_10046770(actor);
					actor->ClearController();
				}

				CharacterManager()->FUN_10083db0(roi);

				if (m_unk0x3c[i].m_unk0x14) {
					m_unk0x3c[i].m_unk0x14 = FALSE;

					MxS32 vehicleId = g_characters[m_unk0x3c[i].m_characterId].m_vehicleId;
					if (vehicleId >= 0) {
						g_vehicles[vehicleId].m_unk0x05 = FALSE;

						LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
						if (roi != NULL) {
							roi->SetVisibility(FALSE);
						}
					}
				}

				m_unk0x3c[i].m_roi = NULL;
				g_characters[m_unk0x3c[i].m_characterId].m_unk0x04 = FALSE;
				g_characters[m_unk0x3c[i].m_characterId].m_unk0x07 = FALSE;
				m_unk0x3c[i].m_characterId = -1;
				m_unk0x3c[i].m_unk0x0d = FALSE;
				m_unk0x414--;
			}
		}

		m_unk0x401 = FALSE;
	}

	MxLong time = Timer()->GetTime();
	float speed = actor->GetWorldSpeed();

	FUN_10064b50(time);

	if (!m_unk0x39 && time - m_unk0x404 > 10000 && speed < g_unk0x100f74b0[0][0] && speed > g_unk0x100f74b0[5][0]) {
		LegoPathBoundary* boundary = actor->GetBoundary();

		Mx3DPointFloat position(roi->GetWorldPosition());
		Mx3DPointFloat direction(roi->GetWorldDirection());

		MxU8 unk0x0c = 0;
		MxU8 actorId = GameState()->GetActorId();

		if (actorId <= 5) {
			unk0x0c = g_unk0x100d8b28[actorId];
		}

		for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
			LegoROI* roi = m_unk0x3c[i].m_roi;

			if (roi != NULL) {
				MxU16 result = FUN_10062110(roi, direction, position, boundary, speed, unk0x0c, m_unk0x3c[i].m_unk0x14);

				if (result) {
					MxMatrix mat;
					mat = roi->GetLocal2World();

					if (FUN_100605e0(result & USHRT_MAX, FALSE, &mat, TRUE, roi, FALSE, TRUE, TRUE, TRUE) == SUCCESS) {
						m_unk0x404 = time;
						return SUCCESS;
					}
				}
			}
		}
	}

	if (time - m_unk0x40c > 1000) {
		FUN_10063d10();
		m_unk0x40c = time;
	}

	if (time - m_unk0x408 < m_unk0x410) {
		return SUCCESS;
	}

	m_unk0x410 = (rand() * 10000 / SHRT_MAX) + 5000;
	m_unk0x408 = time;

	if (time - m_unk0x404 > 10000) {
		FUN_100629b0(-1, FALSE);
	}

	double elapsedSeconds = VideoManager()->GetElapsedSeconds();

	if (elapsedSeconds < 1.0 && elapsedSeconds > 0.01) {
		g_unk0x100f7500 = (g_unk0x100f7500 * 2.0 + elapsedSeconds) / 3.0;

		if (elapsedSeconds > 0.2 && m_numAllowedExtras > 2) {
			m_numAllowedExtras--;
		}
		else if (g_unk0x100f7500 < 0.16 && m_numAllowedExtras < m_unk0x41c) {
			m_numAllowedExtras++;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10062110
// FUNCTION: BETA10 0x10042f41
MxU16 LegoAnimationManager::FUN_10062110(
	LegoROI* p_roi,
	Vector3& p_direction,
	Vector3& p_position,
	LegoPathBoundary* p_boundary,
	float p_speed,
	MxU8 p_unk0x0c,
	MxBool p_unk0x14
)
{
	LegoPathActor* actor = (LegoPathActor*) p_roi->GetEntity();

	if (actor != NULL && actor->GetBoundary() == p_boundary && actor->GetState() == 0) {
		if (GetViewManager()->FUN_100a6150(p_roi->GetWorldBoundingBox())) {
			Mx3DPointFloat direction(p_roi->GetWorldDirection());

			if (direction.Dot(&direction, &p_direction) > 0.707) {
				Mx3DPointFloat position(p_roi->GetWorldPosition());

				// TODO: Fix call
				((Vector3&) position).Sub(&p_position);
				float len = position.LenSquared();
				float min, max;

				for (MxU32 i = 0; i < _countof(g_unk0x100f74b0); i++) {
					if (g_unk0x100f74b0[i][0] < p_speed) {
						max = g_unk0x100f74b0[i][1];
						min = g_unk0x100f74b0[i][2];
						break;
					}
				}

				if (len < max && len > min) {
					MxS8 index = GetCharacterIndex(p_roi->GetName());

					for (MxU16 i = m_unk0x0e; i <= m_unk0x10; i++) {
						if (m_anims[i].m_unk0x28 == index && m_anims[i].m_unk0x0c & p_unk0x0c && m_anims[i].m_unk0x29) {
							MxS32 vehicleId = g_characters[index].m_vehicleId;
							if (vehicleId >= 0) {
								MxBool found = FALSE;

								for (MxS32 j = 0; j < (MxS32) _countof(m_anims[i].m_unk0x2a); j++) {
									if (m_anims[i].m_unk0x2a[j] == vehicleId) {
										found = TRUE;
										break;
									}
								}

								if (p_unk0x14 != found) {
									continue;
								}
							}

							MxU16 result = i;
							MxU16 unk0x22 = m_anims[i].m_unk0x22;

							for (i = i + 1; i <= m_unk0x10; i++) {
								if (m_anims[i].m_unk0x28 == index && m_anims[i].m_unk0x0c & p_unk0x0c &&
									m_anims[i].m_unk0x29 && m_anims[i].m_unk0x22 < unk0x22) {
									result = i;
									unk0x22 = m_anims[i].m_unk0x22;
								}
							}

							return result;
						}
					}
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10062360
// FUNCTION: BETA10 0x100432dd
MxS8 LegoAnimationManager::GetCharacterIndex(const char* p_name)
{
	MxS8 i;

	for (i = 0; i < _countof(g_characters); i++) {
		if (!strnicmp(p_name, g_characters[i].m_name, 2)) {
			return i;
		}
	}

	return -1;
}

// FUNCTION: LEGO1 0x100623a0
// FUNCTION: BETA10 0x10043342
MxBool LegoAnimationManager::FUN_100623a0(AnimInfo& p_info)
{
	LegoWorld* world = CurrentWorld();

	if (world != NULL) {
		LegoEntityList* entityList = world->GetEntityList();

		if (entityList != NULL) {
			Mx3DPointFloat position(p_info.m_unk0x10[0], p_info.m_unk0x10[1], p_info.m_unk0x10[2]);
			float und = p_info.m_unk0x10[3];

			LegoEntityListCursor cursor(entityList);
			LegoEntity* entity;
			IslePathActor* actor = CurrentActor();

			while (cursor.Next(entity)) {
				if (entity != actor && entity->IsA("LegoPathActor")) {
					LegoROI* roi = entity->GetROI();

					if (roi->GetVisibility() && FUN_10062650(position, und, roi)) {
						if (!ModelExists(p_info, roi->GetName())) {
							return TRUE;
						}
					}
				}
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10062520
// FUNCTION: BETA10 0x100434bf
MxBool LegoAnimationManager::ModelExists(AnimInfo& p_info, const char* p_name)
{
	ModelInfo* models = p_info.m_models;
	MxU8 modelCount = p_info.m_modelCount;

	if (models != NULL && modelCount) {
		for (MxU8 i = 0; i < modelCount; i++) {
			if (!strcmpi(models[i].m_name, p_name)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// STUB: LEGO1 0x10062580
// FUNCTION: BETA10 0x10043552
void LegoAnimationManager::FUN_10062580(AnimInfo& p_info)
{
	// TODO
}

// FUNCTION: LEGO1 0x10062650
// FUNCTION: BETA10 0x100436e2
MxBool LegoAnimationManager::FUN_10062650(Vector3& p_position, float p_und, LegoROI* p_roi)
{
	if (p_roi != NULL) {
		Mx3DPointFloat position(p_position);

		// TODO: Fix call
		((Vector3&) position).Sub(p_roi->GetWorldPosition());

		float len = position.LenSquared();
		if (len <= 0.0f) {
			return TRUE;
		}

		len = sqrt(len);
		float radius = p_roi->GetWorldBoundingSphere().Radius();

		if (radius + p_und >= len) {
			return TRUE;
		}
	}

	return FALSE;
}

// STUB: LEGO1 0x10062710
// FUNCTION: BETA10 0x10043787
MxBool LegoAnimationManager::FUN_10062710(AnimInfo& p_info)
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10062770
// FUNCTION: BETA10 0x1004381a
void LegoAnimationManager::FUN_10062770()
{
	if (!m_unk0x38) {
		LegoWorld* world = CurrentWorld();

		if (world != NULL) {
			m_unk0x28[1] = (MxPresenter*) world->Find("MxSoundPresenter", "TransitionSound1");
			m_unk0x28[0] = (MxPresenter*) world->Find("MxSoundPresenter", "TransitionSound2");
			m_unk0x30[1] = 200;
			m_unk0x30[0] = 750;
			m_unk0x38 = TRUE;
		}
	}
}

// STUB: LEGO1 0x100627d0
void LegoAnimationManager::FUN_100627d0(MxBool)
{
	// TODO
}

// STUB: LEGO1 0x100629b0
// FUNCTION: BETA10 0x10043c10
void LegoAnimationManager::FUN_100629b0(MxU32, MxBool)
{
	// TODO
}

// STUB: LEGO1 0x10063270
void LegoAnimationManager::FUN_10063270(LegoROIList*, LegoAnimPresenter*)
{
	// TODO
}

// FUNCTION: LEGO1 0x10063780
void LegoAnimationManager::FUN_10063780(LegoROIList* p_list)
{
	if (p_list != NULL && m_unk0x424 != NULL) {
		LegoROIListCursor cursor(p_list);
		LegoROI* roi;

		while (cursor.Next(roi)) {
			const char* name = roi->GetName();

			if (CharacterManager()->Exists(name)) {
				m_unk0x424->Append(roi);
				cursor.Detach();
			}
		}
	}
}

// FUNCTION: LEGO1 0x10063aa0
void LegoAnimationManager::FUN_10063aa0()
{
	LegoROIListCursor cursor(m_unk0x424);
	LegoROI* roi;

	while (cursor.Next(roi)) {
		CharacterManager()->FUN_10083db0(roi);
	}
}

// STUB: LEGO1 0x10063d10
// FUNCTION: BETA10 0x10045034
void LegoAnimationManager::FUN_10063d10()
{
	// TODO
}

// STUB: LEGO1 0x10064670
void LegoAnimationManager::FUN_10064670(Vector3*)
{
	// TODO
}

// STUB: LEGO1 0x10064740
void LegoAnimationManager::FUN_10064740(Vector3*)
{
	// TODO
}

// STUB: LEGO1 0x100648f0
// FUNCTION: BETA10 0x10045daf
void LegoAnimationManager::FUN_100648f0(LegoTranInfo*, MxLong)
{
	// TODO
}

// STUB: LEGO1 0x10064b50
// FUNCTION: BETA10 0x10045f14
void LegoAnimationManager::FUN_10064b50(MxLong p_time)
{
	// TODO
}
