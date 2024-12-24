#include "legoanimationmanager.h"

#include "3dmanager/lego3dmanager.h"
#include "anim/legoanim.h"
#include "define.h"
#include "islepathactor.h"
#include "legoanimmmpresenter.h"
#include "legoanimpresenter.h"
#include "legocharactermanager.h"
#include "legoendanimnotificationparam.h"
#include "legoentitylist.h"
#include "legoextraactor.h"
#include "legogamestate.h"
#include "legolocomotionanimpresenter.h"
#include "legomain.h"
#include "legonavcontroller.h"
#include "legoroilist.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "realtime/realtime.h"
#include "viewmanager/viewmanager.h"

#include <io.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(LegoAnimationManager, 0x500)
DECOMP_SIZE_ASSERT(LegoAnimationManager::Character, 0x18)
DECOMP_SIZE_ASSERT(LegoAnimationManager::Vehicle, 0x08)
DECOMP_SIZE_ASSERT(LegoAnimationManager::Extra, 0x18)
DECOMP_SIZE_ASSERT(LegoTranInfo, 0x78)
DECOMP_SIZE_ASSERT(AnimState, 0x1c)
DECOMP_SIZE_ASSERT(AnimInfo, 0x30)
DECOMP_SIZE_ASSERT(ModelInfo, 0x30)

// GLOBAL: LEGO1 0x100d8b28
MxU8 g_unk0x100d8b28[] = {0, 1, 2, 4, 8, 16};

// GLOBAL: LEGO1 0x100f6d20
LegoAnimationManager::Vehicle g_vehicles[] = {
	{"bikebd", 0, FALSE},
	{"bikepg", 0, FALSE},
	{"bikerd", 0, FALSE},
	{"bikesy", 0, FALSE},
	{"motoni", 0, FALSE},
	{"motola", 0, FALSE},
	{"board", 0, FALSE}
};

// GLOBAL: LEGO1 0x100f6d58
const char* g_cycles[11][17] = {
	{"CNs001xx",
	 "CNs002xx",
	 "CNs003xx",
	 "CNs004xx",
	 "CNs005xx",
	 "CNs007xx",
	 "CNs006xx",
	 "CNs008xx",
	 "CNs009xx",
	 "CNs010xx",
	 "CNs011xx",
	 "CNs012xx",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001Pe",
	 "CNs002Pe",
	 "CNs003Pe",
	 "CNs004Pe",
	 "CNs005Pe",
	 "CNs007Pe",
	 "CNs006Pe",
	 "CNs008Pe",
	 "CNs009Pe",
	 "CNs010Pe",
	 "CNs001sk",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001Ma",
	 "CNs002Ma",
	 "CNs003Ma",
	 "CNs004Ma",
	 "CNs005Ma",
	 "CNs007Ma",
	 "CNs006Ma",
	 "CNs008Ma",
	 "CNs009Ma",
	 "CNs010Ma",
	 "CNs0x4Ma",
	 NULL,
	 NULL,
	 "CNs011Ma",
	 "CNs012Ma",
	 "CNs013Ma",
	 NULL},
	{"CNs001Pa",
	 "CNs002Pa",
	 "CNs003Pa",
	 "CNs004Pa",
	 "CNs005Pa",
	 "CNs007Pa",
	 "CNs006Pa",
	 "CNs008Pa",
	 "CNs009Pa",
	 "CNs010Pa",
	 "CNs0x4Pa",
	 NULL,
	 NULL,
	 "CNs011Pa",
	 "CNs012Pa",
	 "CNs013Pa",
	 NULL},
	{"CNs001Ni",
	 "CNs002Ni",
	 "CNs003Ni",
	 "CNs004Ni",
	 "CNs005Ni",
	 "CNs007Ni",
	 "CNs006Ni",
	 "CNs008Ni",
	 "CNs009Ni",
	 "CNs010Ni",
	 "CNs011Ni",
	 "CNsx11Ni",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001La",
	 "CNs002La",
	 "CNs003La",
	 "CNs004La",
	 "CNs005La",
	 "CNs007La",
	 "CNs006La",
	 "CNs008La",
	 "CNs009La",
	 "CNs010La",
	 "CNs011La",
	 "CNsx11La",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001Br",
	 "CNs002Br",
	 "CNs003Br",
	 "CNs004Br",
	 "CNs005Br",
	 "CNs007Br",
	 "CNs006Br",
	 "CNs008Br",
	 "CNs009Br",
	 "CNs010Br",
	 "CNs011Br",
	 "CNs900Br",
	 "CNs901Br",
	 "CNs011Br",
	 "CNs012Br",
	 "CNs013Br",
	 "CNs014Br"},
	{"CNs001xx",
	 "CNs002xx",
	 "CNs003xx",
	 "CNs004xx",
	 "CNs005xx",
	 "CNs007xx",
	 "CNs006xx",
	 "CNs008xx",
	 "CNs009xx",
	 "CNs010xx",
	 "CNs001Bd",
	 "CNs012xx",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001xx",
	 "CNs002xx",
	 "CNs003xx",
	 "CNs004xx",
	 "CNs005xx",
	 "CNs007xx",
	 "CNs006xx",
	 "CNs008xx",
	 "CNs009xx",
	 "CNs010xx",
	 "CNs001Pg",
	 "CNs012xx",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001xx",
	 "CNs002xx",
	 "CNs003xx",
	 "CNs004xx",
	 "CNs005xx",
	 "CNs007xx",
	 "CNs006xx",
	 "CNs008xx",
	 "CNs009xx",
	 "CNs010xx",
	 "CNs001Rd",
	 "CNs012xx",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},
	{"CNs001xx",
	 "CNs002xx",
	 "CNs003xx",
	 "CNs004xx",
	 "CNs005xx",
	 "CNs007xx",
	 "CNs006xx",
	 "CNs008xx",
	 "CNs009xx",
	 "CNs010xx",
	 "CNs001Sy",
	 "CNs012xx",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL}
};

// GLOBAL: LEGO1 0x100f7048
// GLOBAL: BETA10 0x101e1ee8
LegoAnimationManager::Character g_characters[47] = {
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

// GLOBAL: LEGO1 0x100f7504
MxS32 g_unk0x100f7504 = 0;

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

	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
		LegoROI* roi = m_extras[i].m_roi;

		if (roi != NULL) {
			LegoPathActor* actor = CharacterManager()->GetExtraActor(roi->GetName());

			if (actor != NULL && actor->GetController() != NULL && CurrentWorld() != NULL) {
				CurrentWorld()->RemoveActor(actor);
				actor->SetController(NULL);
			}

			CharacterManager()->ReleaseActor(roi);
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
		m_animState->Reset();
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
	m_suspendedEnableCamAnims = m_enableCamAnims;
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

	if (m_worldId == LegoOmni::e_act1) {
		m_animState->InitFromAnims(m_animCount, m_anims, m_lastExtraCharacterId);
	}

	if (!m_suspended) {
		m_suspended = TRUE;
		m_suspendedEnableCamAnims = m_enableCamAnims;
		m_unk0x429 = m_unk0x400;
		m_unk0x42a = m_unk0x402;
		m_unk0x402 = FALSE;

		FUN_10061010(FALSE);

		MxS32 i;
		for (i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
			LegoROI* roi = m_extras[i].m_roi;

			if (roi != NULL) {
				LegoPathActor* actor = CharacterManager()->GetExtraActor(roi->GetName());

				if (actor != NULL && actor->GetController() != NULL) {
					actor->GetController()->RemoveActor(actor);
					actor->SetController(NULL);
				}

				CharacterManager()->ReleaseActor(roi);
			}

			if (m_extras[i].m_unk0x14) {
				m_extras[i].m_unk0x14 = FALSE;

				MxS32 vehicleId = g_characters[m_extras[i].m_characterId].m_vehicleId;
				if (vehicleId >= 0) {
					g_vehicles[vehicleId].m_unk0x05 = FALSE;

					LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
					if (roi != NULL) {
						roi->SetVisibility(FALSE);
					}
				}
			}

			m_extras[i].m_roi = NULL;
			m_extras[i].m_characterId = -1;
			m_extras[i].m_speed = -1.0f;
		}

		m_unk0x18 = 0;
		m_unk0x1a = FALSE;
		m_enableCamAnims = FALSE;
		m_unk0x400 = FALSE;
		m_unk0x414 = 0;
		m_unk0x401 = FALSE;

		for (i = 0; i < (MxS32) sizeOfArray(g_characters); i++) {
			g_characters[i].m_inExtras = FALSE;
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
		m_enableCamAnims = m_suspendedEnableCamAnims;
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
	m_worldId = LegoOmni::e_undefined;
	m_animCount = 0;
	m_anims = NULL;
	m_unk0x18 = 0;
	m_unk0x1a = FALSE;
	m_tranInfoList = NULL;
	m_tranInfoList2 = NULL;
	m_unk0x41c = g_legoAnimationManagerConfig <= 1 ? 10 : 20;

	MxS32 i;
	for (i = 0; i < (MxS32) sizeOfArray(m_unk0x28); i++) {
		m_unk0x28[i] = NULL;
		m_unk0x30[i] = 0;
	}

	for (i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
		m_extras[i].m_roi = NULL;
		m_extras[i].m_characterId = -1;
		m_extras[i].m_speed = -1.0f;
		m_extras[i].m_unk0x14 = FALSE;
	}

	m_unk0x38 = FALSE;
	m_animRunning = FALSE;
	m_enableCamAnims = TRUE;
	m_lastExtraCharacterId = 0;
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

	for (i = 0; i < (MxS32) sizeOfArray(g_characters); i++) {
		g_characters[i].m_active = FALSE;
		g_characters[i].m_inExtras = FALSE;
	}

	for (i = 0; i < (MxS32) sizeOfArray(g_vehicles); i++) {
		g_vehicles[i].m_unk0x04 = FALSE;
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
			PurgeExtra(TRUE);
		}
	}
}

// FUNCTION: LEGO1 0x1005f700
// FUNCTION: BETA10 0x1004024c
void LegoAnimationManager::EnableCamAnims(MxBool p_enableCamAnims)
{
	if (m_suspended) {
		m_suspendedEnableCamAnims = p_enableCamAnims;
	}
	else {
		m_enableCamAnims = p_enableCamAnims;
	}
}

// FUNCTION: LEGO1 0x1005f720
MxResult LegoAnimationManager::LoadWorldInfo(LegoOmni::World p_worldId)
{
	MxResult result = FAILURE;
	MxS32 i, j, k;

	if (m_worldId != p_worldId) {
		if (m_tranInfoList != NULL) {
			delete m_tranInfoList;
			m_tranInfoList = NULL;
		}

		if (m_tranInfoList2 != NULL) {
			delete m_tranInfoList2;
			m_tranInfoList2 = NULL;
		}

		for (i = 0; i < (MxS32) sizeOfArray(m_unk0x28); i++) {
			m_unk0x28[i] = NULL;
			m_unk0x30[i] = 0;
		}

		m_unk0x38 = FALSE;
		m_animRunning = FALSE;
		m_unk0x430 = FALSE;
		m_unk0x42c = NULL;

		for (j = 0; j < (MxS32) sizeOfArray(g_characters); j++) {
			g_characters[j].m_active = FALSE;
		}

		m_animState = (AnimState*) GameState()->GetState("AnimState");
		if (m_animState == NULL) {
			m_animState = (AnimState*) GameState()->CreateState("AnimState");
		}

		if (m_worldId == LegoOmni::e_act1) {
			m_animState->InitFromAnims(m_animCount, m_anims, m_lastExtraCharacterId);
		}

		DeleteAnimations();

		LegoFile file;

		if (p_worldId == LegoOmni::e_undefined) {
			result = SUCCESS;
			goto done;
		}

		char filename[128];
		char path[1024];
		sprintf(filename, "lego\\data\\%sinf.dta", Lego()->GetWorldName(p_worldId));
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

			if (m_anims[j].m_location == -1) {
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

		m_worldId = p_worldId;
		m_tranInfoList = new LegoTranInfoList();
		m_tranInfoList2 = new LegoTranInfoList();

		FUN_100617c0(-1, m_unk0x0e, m_unk0x10);

		result = SUCCESS;
		m_unk0x402 = TRUE;

		if (m_suspended) {
			m_suspendedEnableCamAnims = m_enableCamAnims;
			m_unk0x429 = m_unk0x400;
			m_unk0x42a = TRUE;
			m_enableCamAnims = FALSE;
			m_unk0x400 = FALSE;
			m_unk0x402 = FALSE;
		}

		if (p_worldId == 0) {
			m_animState->CopyToAnims(m_animCount, m_anims, m_lastExtraCharacterId);
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
	for (MxS32 i = 0; i < sizeOfArray(g_vehicles); i++) {
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

	if (p_file->Read(&p_info->m_location, sizeof(p_info->m_location)) == FAILURE) {
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

	for (i = 0; i < (MxS32) sizeOfArray(p_info->m_unk0x10); i++) {
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

// FUNCTION: LEGO1 0x10060480
// FUNCTION: BETA10 0x100412a9
void LegoAnimationManager::FUN_10060480(const LegoChar* p_characterNames[], MxU32 p_numCharacterNames)
{
	for (MxS32 i = 0; i < p_numCharacterNames; i++) {
		for (MxS32 j = 0; j < sizeOfArray(g_characters); j++) {
			if (!stricmp(g_characters[j].m_name, p_characterNames[i])) {
				g_characters[j].m_unk0x08 = TRUE;
			}
		}
	}
}

// FUNCTION: LEGO1 0x100604d0
// FUNCTION: BETA10 0x10041335
void LegoAnimationManager::FUN_100604d0(MxBool p_unk0x08)
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(g_characters); i++) {
		g_characters[i].m_unk0x08 = p_unk0x08;
	}
}

// FUNCTION: LEGO1 0x100604f0
// FUNCTION: BETA10 0x1004137b
void LegoAnimationManager::FUN_100604f0(MxS32 p_objectIds[], MxU32 p_numObjectIds)
{
	for (MxS32 i = 0; i < p_numObjectIds; i++) {
		for (MxS32 j = 0; j < m_animCount; j++) {
			if (m_anims[j].m_objectId == p_objectIds[i]) {
				m_anims[j].m_unk0x29 = TRUE;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10060540
// FUNCTION: BETA10 0x1004140f
void LegoAnimationManager::FUN_10060540(MxBool p_unk0x29)
{
	for (MxS32 i = 0; i < m_animCount; i++) {
		m_anims[i].m_unk0x29 = p_unk0x29;
	}
}

// FUNCTION: LEGO1 0x10060570
// FUNCTION: BETA10 0x10041463
void LegoAnimationManager::FUN_10060570(MxBool p_unk0x1a)
{
	m_animRunning = FALSE;
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

	if (m_worldId != LegoOmni::e_undefined && p_index < m_animCount && m_tranInfoList != NULL) {
		PurgeExtra(FALSE);
		FUN_10062770();

		MxDSAction action;
		AnimInfo& animInfo = m_anims[p_index];

		if (!p_bool1) {
			if (m_animRunning || !animInfo.m_unk0x29) {
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
		tranInfo->m_location = m_anims[p_index].m_location;
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

		action.SetAtomId(*Lego()->GetWorldAtom(m_worldId));
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
				LegoPathActor* actor = UserActor();

				if (actor != NULL) {
					actor->SetActorState(LegoPathActor::c_disabled);
					actor->SetWorldSpeed(0.0f);
				}
			}

			m_animRunning = TRUE;
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

	PurgeExtra(FALSE);

	LegoTranInfo* info = new LegoTranInfo();
	info->m_animInfo = NULL;
	info->m_index = ++m_unk0x1c;
	info->m_unk0x10 = 0;
	info->m_unk0x08 = NULL;
	info->m_location = -1;
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

	action.SetAtomId(*Lego()->GetWorldAtom(m_worldId));
	action.SetObjectId(p_objectId);
	action.SetUnknown24(-1);
	action.AppendExtra(strlen(buf) + 1, buf);

	if (StartActionIfUnknown0x13c(action) == SUCCESS) {
		BackgroundAudioManager()->LowerVolume();
		info->m_flags |= LegoTranInfo::c_bit2;
		m_animRunning = TRUE;
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

	if (p_entity->GetType() == LegoEntity::e_actor) {
		LegoPathActor* actor = CharacterManager()->GetExtraActor(roi->GetName());

		if (actor) {
			LegoPathController* controller = actor->GetController();

			if (controller) {
				controller->RemoveActor(actor);
				actor->SetController(NULL);

				for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
					if (m_extras[i].m_roi == roi) {
						MxS32 characterId = m_extras[i].m_characterId;
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
	MxU32 p_objectId,
	MxMatrix* p_matrix,
	MxBool p_param3,
	MxU8 p_param4,
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
			case e_unk0:
				unk0x0a = m_anims[i].m_unk0x0a;
				break;
			case e_unk1:
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

// FUNCTION: LEGO1 0x10060eb0
// FUNCTION: BETA10 0x1004206c
void LegoAnimationManager::CameraTriggerFire(LegoPathActor* p_actor, MxBool, MxU32 p_location, MxBool p_bool)
{
	if (Lego()->m_unk0x13c && m_enableCamAnims && !m_animRunning) {
		LegoLocation* location = LegoNavController::GetLocation(p_location);

		if (location != NULL) {
			if (location->m_frequency == 0) {
				return;
			}

			if (location->m_unk0x5c && location->m_frequency < rand() % 100) {
				return;
			}
		}

		MxU16 unk0x0e, unk0x10;
		if (FUN_100617c0(p_location, unk0x0e, unk0x10) == SUCCESS) {
			MxU16 index = unk0x0e;
			MxU32 unk0x22 = -1;
			MxBool success = FALSE;

			for (MxU16 i = unk0x0e; i <= unk0x10; i++) {
				AnimInfo& animInfo = m_anims[i];

				if ((p_bool || !FUN_100623a0(animInfo)) && !FUN_10062710(animInfo) && animInfo.m_unk0x29 &&
					animInfo.m_unk0x22 < unk0x22 && (animInfo.m_unk0x22 == 0 || *animInfo.m_name != 'i') &&
					*animInfo.m_name != 'I') {
					index = i;
					unk0x22 = animInfo.m_unk0x22;
					success = TRUE;
				}
			}

			if (success) {
				FUN_100605e0(index, m_anims[index].m_unk0x0a, NULL, TRUE, NULL, FALSE, TRUE, TRUE, TRUE);
				location->m_unk0x5c = TRUE;
			}
		}
	}
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

				if (tranInfo->m_unk0x14 && tranInfo->m_location != -1 && p_und) {
					LegoAnim* anim;

					if (tranInfo->m_presenter->GetPresenter() != NULL &&
						(anim = tranInfo->m_presenter->GetPresenter()->GetAnimation()) != NULL &&
						anim->GetCamAnim() != NULL) {
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

	m_animRunning = unk0x39;
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
MxResult LegoAnimationManager::FUN_100617c0(MxS32 p_location, MxU16& p_unk0x0e, MxU16& p_unk0x10)
{
	MxResult result = FAILURE;
	MxU16 unk0x0e = 0;
	MxU16 unk0x10 = 0;
	MxBool success = FALSE;

	if (p_location == -1) {
		MxS32 i;

		for (i = 0; i < m_animCount; i++) {
			if (m_anims[i].m_location == p_location) {
				unk0x0e = i;
				success = TRUE;
				break;
			}
		}

		if (success) {
			for (; i < m_animCount && m_anims[i].m_location == p_location; i++) {
				unk0x10 = i;
			}
		}
	}
	else {
		MxS32 i;

		for (i = 0; m_animCount > i && m_anims[i].m_location != -1; i++) {
			if (m_anims[i].m_location == p_location) {
				unk0x0e = i;
				success = TRUE;
				break;
			}
		}

		if (success) {
			for (; i < m_animCount && m_anims[i].m_location == p_location; i++) {
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
		if (((MxNotificationParam&) p_param).GetNotification() == c_notificationEndAnim) {
			FUN_100605e0(m_unk0x18, TRUE, NULL, TRUE, NULL, FALSE, TRUE, TRUE, TRUE);
		}
	}
	else if (((MxNotificationParam&) p_param).GetNotification() == c_notificationEndAnim && m_tranInfoList != NULL) {
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

				m_animRunning = FALSE;
				m_unk0x404 = Timer()->GetTime();

				found = TRUE;
				cursor.Detach();
				delete tranInfo;

				for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
					LegoROI* roi = m_extras[i].m_roi;

					if (roi != NULL) {
						LegoExtraActor* actor = CharacterManager()->GetExtraActor(roi->GetName());
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

	LegoPathActor* actor = UserActor();
	LegoROI* roi;

	if (actor == NULL || (roi = actor->GetROI()) == NULL) {
		return SUCCESS;
	}

	if (m_unk0x401) {
		for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
			LegoROI* roi = m_extras[i].m_roi;

			if (roi != NULL && m_extras[i].m_unk0x0d) {
				LegoPathActor* actor = CharacterManager()->GetExtraActor(roi->GetName());

				if (actor != NULL && actor->GetController() != NULL) {
					actor->GetController()->RemoveActor(actor);
					actor->SetController(NULL);
				}

				CharacterManager()->ReleaseActor(roi);

				if (m_extras[i].m_unk0x14) {
					m_extras[i].m_unk0x14 = FALSE;

					MxS32 vehicleId = g_characters[m_extras[i].m_characterId].m_vehicleId;
					if (vehicleId >= 0) {
						g_vehicles[vehicleId].m_unk0x05 = FALSE;

						LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
						if (roi != NULL) {
							roi->SetVisibility(FALSE);
						}
					}
				}

				m_extras[i].m_roi = NULL;
				g_characters[m_extras[i].m_characterId].m_inExtras = FALSE;
				g_characters[m_extras[i].m_characterId].m_unk0x07 = FALSE;
				m_extras[i].m_characterId = -1;
				m_extras[i].m_unk0x0d = FALSE;
				m_unk0x414--;
			}
		}

		m_unk0x401 = FALSE;
	}

	MxLong time = Timer()->GetTime();
	float speed = actor->GetWorldSpeed();

	FUN_10064b50(time);

	if (!m_animRunning && time - m_unk0x404 > 10000 && speed < g_unk0x100f74b0[0][0] && speed > g_unk0x100f74b0[5][0]) {
		LegoPathBoundary* boundary = actor->GetBoundary();

		Mx3DPointFloat position(roi->GetWorldPosition());
		Mx3DPointFloat direction(roi->GetWorldDirection());

		MxU8 unk0x0c = 0;
		MxU8 actorId = GameState()->GetActorId();

		if (actorId <= LegoActor::c_laura) {
			unk0x0c = g_unk0x100d8b28[actorId];
		}

		for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
			LegoROI* roi = m_extras[i].m_roi;

			if (roi != NULL) {
				MxU16 result = FUN_10062110(roi, direction, position, boundary, speed, unk0x0c, m_extras[i].m_unk0x14);

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
		AddExtra(-1, FALSE);
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

	if (actor != NULL && actor->GetBoundary() == p_boundary && actor->GetActorState() == LegoPathActor::c_initial) {
		if (GetViewManager()->IsBoundingBoxInFrustum(p_roi->GetWorldBoundingBox())) {
			Mx3DPointFloat direction(p_roi->GetWorldDirection());

			if (direction.Dot(&direction, &p_direction) > 0.707) {
				Mx3DPointFloat position(p_roi->GetWorldPosition());

				position -= p_position;
				float len = position.LenSquared();
				float min, max;

				for (MxU32 i = 0; i < sizeOfArray(g_unk0x100f74b0); i++) {
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

								for (MxS32 j = 0; j < (MxS32) sizeOfArray(m_anims[i].m_unk0x2a); j++) {
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

	for (i = 0; i < sizeOfArray(g_characters); i++) {
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
			LegoPathActor* actor = UserActor();

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

// FUNCTION: LEGO1 0x10062580
// FUNCTION: BETA10 0x10043552
void LegoAnimationManager::FUN_10062580(AnimInfo& p_info)
{
	ModelInfo* models = p_info.m_models;
	MxU8 modelCount = p_info.m_modelCount;

	if (models != NULL && modelCount) {
		for (MxU8 i = 0; i < modelCount; i++) {
			LegoPathActor* actor = CharacterManager()->GetExtraActor(models[i].m_name);

			if (actor) {
				LegoPathController* controller = actor->GetController();

				if (controller) {
					controller->RemoveActor(actor);
					actor->SetController(NULL);

					for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
						if (m_extras[i].m_roi == actor->GetROI()) {
							MxS32 characterId = m_extras[i].m_characterId;
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
	}
}

// FUNCTION: LEGO1 0x10062650
// FUNCTION: BETA10 0x100436e2
MxBool LegoAnimationManager::FUN_10062650(Vector3& p_position, float p_und, LegoROI* p_roi)
{
	if (p_roi != NULL) {
		Mx3DPointFloat position(p_position);
		position -= p_roi->GetWorldPosition();

		float len = position.LenSquared();
		if (len <= 0.0f) {
			return TRUE;
		}

		len = sqrt(len);
		if (p_roi->GetWorldBoundingSphere().Radius() + p_und >= len) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10062710
// FUNCTION: BETA10 0x10043787
MxBool LegoAnimationManager::FUN_10062710(AnimInfo& p_info)
{
	MxU8 und = 0;
	MxU8 actorId = GameState()->GetActorId();

	if (actorId <= LegoActor::c_laura) {
		und = g_unk0x100d8b28[actorId];
	}

	if (!(und & p_info.m_unk0x0c)) {
		return TRUE;
	}

	if (ModelExists(p_info, GameState()->GetActorName())) {
		return TRUE;
	}

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

// FUNCTION: LEGO1 0x100627d0
// FUNCTION: BETA10 0x1004389d
void LegoAnimationManager::PurgeExtra(MxBool p_und)
{
	ViewManager* viewManager = GetViewManager();

	if (p_und || viewManager != NULL) {
		MxLong time = Timer()->GetTime();

		for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
			LegoROI* roi = m_extras[i].m_roi;

			if (roi != NULL) {
				MxU16 prefix = *(MxU16*) roi->GetName();
				MxLong und = ((m_numAllowedExtras - 2) * 280000 / 18) + 20000;
				MxBool maOrPa = prefix == TWOCC('m', 'a') || prefix == TWOCC('p', 'a');

				if ((p_und && !maOrPa) ||
					(g_characters[m_extras[i].m_characterId].m_unk0x10 >= 0 && time - m_extras[i].m_unk0x08 > und &&
					 CharacterManager()->GetRefCount(roi) == 1 &&
					 !viewManager->IsBoundingBoxInFrustum(roi->GetWorldBoundingBox()))) {
					m_unk0x414--;

					LegoPathActor* actor = CharacterManager()->GetExtraActor(roi->GetName());
					if (actor != NULL && actor->GetController() != NULL) {
						actor->GetController()->RemoveActor(actor);
						actor->SetController(NULL);
					}

					CharacterManager()->ReleaseActor(roi);

					if (m_extras[i].m_unk0x14) {
						m_extras[i].m_unk0x14 = FALSE;

						MxS32 vehicleId = g_characters[m_extras[i].m_characterId].m_vehicleId;
						if (vehicleId >= 0) {
							g_vehicles[vehicleId].m_unk0x05 = FALSE;

							LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
							if (roi != NULL) {
								roi->SetVisibility(FALSE);
							}
						}
					}

					m_extras[i].m_roi = NULL;
					g_characters[m_extras[i].m_characterId].m_inExtras = FALSE;
					g_characters[m_extras[i].m_characterId].m_unk0x07 = FALSE;
					m_extras[i].m_characterId = -1;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100629b0
// FUNCTION: BETA10 0x10043c10
void LegoAnimationManager::AddExtra(MxS32 p_location, MxBool p_und)
{
	LegoLocation::Boundary* boundary = NULL;

	if (p_und || (!m_animRunning && m_unk0x400)) {
		LegoWorld* world = CurrentWorld();

		if (world != NULL) {
			PurgeExtra(FALSE);

			LegoPathActor* actor = UserActor();
			if (actor == NULL || actor->GetWorldSpeed() <= 20.0f) {
				MxU32 i;
				for (i = 0; i < m_numAllowedExtras && m_extras[i].m_roi != NULL; i++) {
				}

				if (i != m_numAllowedExtras) {
					MxU8 und = rand() % 2 != 0 ? 1 : 2;
					MxBool bool1, bool2;

					switch (g_unk0x100f7504 % 4) {
					case 0:
						bool1 = FALSE;
						bool2 = FALSE;
						break;
					case 1:
						bool1 = FALSE;
						bool2 = TRUE;
						break;
					default:
						bool1 = TRUE;
						bool2 = FALSE;
						break;
					}

					if (p_location < 0) {
						boundary = new LegoLocation::Boundary;

						if (!FUN_10064120(boundary, und == 2, bool2)) {
							delete boundary;
							boundary = NULL;
						}
					}
					else {
						LegoLocation* location = LegoNavController::GetLocation(p_location);

						if (location != NULL) {
							if (location->m_boundaryA.m_unk0x10 || FUN_10063fb0(&location->m_boundaryA, world)) {
								boundary = &location->m_boundaryA;
							}
							else if (location->m_boundaryB.m_unk0x10 || FUN_10063fb0(&location->m_boundaryB, world)) {
								boundary = &location->m_boundaryB;
							}
						}

						bool1 = FALSE;
					}

					if (boundary != NULL) {
						for (i = 0; i < m_numAllowedExtras; i++) {
							if (m_extras[i].m_roi == NULL) {
								m_lastExtraCharacterId++;

								if (m_lastExtraCharacterId >= sizeOfArray(g_characters)) {
									m_lastExtraCharacterId = 0;
								}

								MxU32 characterIdStart = m_lastExtraCharacterId;

								MxBool active;
								if (bool1) {
									active = TRUE;
								}
								else {
									active = rand() % 100 < 50;
								}

							tryNextCharacter:
								if (g_characters[m_lastExtraCharacterId].m_unk0x09 &&
									g_characters[m_lastExtraCharacterId].m_unk0x08 &&
									!g_characters[m_lastExtraCharacterId].m_inExtras &&
									g_characters[m_lastExtraCharacterId].m_active == active) {
									if (!CharacterManager()->Exists(g_characters[m_lastExtraCharacterId].m_name)) {
										m_extras[i].m_roi = CharacterManager()->GetActorROI(
											g_characters[m_lastExtraCharacterId].m_name,
											TRUE
										);

										LegoExtraActor* actor = CharacterManager()->GetExtraActor(
											g_characters[m_lastExtraCharacterId].m_name
										);

										switch (g_unk0x100f7504++ % 4) {
										case 0:
											actor->SetUnknown0x0c(und != 1 ? 1 : 2);
											break;
										case 1: {
											actor->SetUnknown0x0c(und);
											MxS32 src = boundary->m_src;
											boundary->m_src = boundary->m_dest;
											boundary->m_dest = src;
											break;
										}
										default:
											actor->SetUnknown0x0c(und);
											break;
										}

										if (world->PlaceActor(
												actor,
												boundary->m_name,
												boundary->m_src,
												boundary->m_srcScale,
												boundary->m_dest,
												boundary->m_destScale
											) == SUCCESS) {
											MxS32 vehicleId = g_characters[m_lastExtraCharacterId].m_vehicleId;
											if (vehicleId >= 0) {
												g_vehicles[vehicleId].m_unk0x04 =
													rand() % 100 < g_characters[m_lastExtraCharacterId].m_unk0x15;
											}

											if (FUN_10063b90(
													world,
													actor,
													CharacterManager()->GetMood(m_extras[i].m_roi),
													m_lastExtraCharacterId
												)) {
												m_extras[i].m_unk0x14 = TRUE;
												g_vehicles[vehicleId].m_unk0x05 = TRUE;
											}
											else {
												m_extras[i].m_unk0x14 = FALSE;
											}

											float speed;
											if (m_extras[i].m_unk0x14) {
												speed = ((float) (rand() * 1.5) / 32767.0f) + 0.9;
											}
											else {
												speed = ((float) (rand() * 1.4) / 32767.0f) + 0.6;
											}

											actor->SetWorldSpeed(speed);

											m_extras[i].m_characterId = m_lastExtraCharacterId;
											g_characters[m_lastExtraCharacterId].m_inExtras = TRUE;
											m_extras[i].m_unk0x08 = Timer()->GetTime();
											m_extras[i].m_speed = -1;
											m_extras[i].m_unk0x0d = FALSE;
											m_unk0x414++;
											return;
										}
										else {
											CharacterManager()->ReleaseActor(m_extras[i].m_roi);
											m_extras[i].m_roi = NULL;
											continue;
										}
									}
								}

								m_lastExtraCharacterId++;

								if (m_lastExtraCharacterId >= sizeOfArray(g_characters)) {
									m_lastExtraCharacterId = 0;
								}

								if (m_lastExtraCharacterId == characterIdStart) {
									return;
								}

								goto tryNextCharacter;
							}
						}
					}
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10062e20
// FUNCTION: BETA10 0x100444cb
MxBool LegoAnimationManager::FUN_10062e20(LegoROI* p_roi, LegoAnimPresenter* p_presenter)
{
	LegoWorld* world = CurrentWorld();

	if (world == NULL || m_suspended || !m_unk0x400) {
		return FALSE;
	}

	MxBool inExtras = FALSE;
	const char* name = p_roi->GetName();

	LegoExtraActor* actor = CharacterManager()->GetExtraActor(name);
	if (actor != NULL) {
		MxS32 characterId = -1;
		MxS32 i;

		for (i = 0; i < (MxS32) sizeOfArray(g_characters); i++) {
			if (!strcmpi(name, g_characters[i].m_name)) {
				characterId = i;
				break;
			}
		}

		if (characterId == -1) {
			return FALSE;
		}

		if (!g_characters[characterId].m_inExtras) {
			for (i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
				if (m_extras[i].m_roi == NULL) {
					m_extras[i].m_roi = p_roi;
					break;
				}
			}

			if (i == (MxS32) sizeOfArray(m_extras)) {
				return FALSE;
			}
		}
		else {
			inExtras = TRUE;

			for (i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
				if (m_extras[i].m_roi == p_roi) {
					break;
				}
			}

			if (i == (MxS32) sizeOfArray(m_extras)) {
				return FALSE;
			}
		}

		if (g_characters[characterId].m_unk0x07) {
			m_unk0x414--;

			if (actor->GetBoundary() == NULL) {
				g_characters[characterId].m_unk0x07 = FALSE;

				if (g_characters[characterId].m_unk0x0c < 0) {
					g_characters[characterId].m_unk0x0c = 0;
				}

				if (g_characters[characterId].m_unk0x10 < 0) {
					g_characters[characterId].m_unk0x10 = 0;
				}

				m_extras[i].m_roi = NULL;
				g_characters[characterId].m_unk0x07 = FALSE;
				g_characters[characterId].m_inExtras = FALSE;
				return FALSE;
			}

			CharacterManager()->ReleaseActor(p_roi);
		}
		else {
			if (inExtras) {
				return FALSE;
			}
		}

		if (GameState()->GetCurrentAct() != LegoGameState::e_act1 && !strcmp(name, "brickstr")) {
			return FALSE;
		}

		MxBool local24 = inExtras && g_characters[characterId].m_unk0x07 &&
						 (g_characters[characterId].m_unk0x0c < 0 || g_characters[characterId].m_unk0x10 < 0);

		MxResult result = 1; // Not a valid MxResult value

		if (!local24) {
			MxU8 unk0x0c;

			switch (rand() % 3) {
			case 0:
				unk0x0c = 1;
				break;
			case 1:
				unk0x0c = 2;
				break;
			case 2:
				unk0x0c = 0;
				break;
			}

			actor->SetUnknown0x0c(unk0x0c);

			Mx3DPointFloat position;
			Mx3DPointFloat direction;

			position = p_roi->GetWorldPosition();
			direction = p_roi->GetWorldDirection();

			direction *= -1.0f;
			m_extras[i].m_speed = -1.0f;

			if (inExtras) {
				actor->ClearMaps();
			}

			if (FUN_10063b90(world, actor, CharacterManager()->GetMood(p_roi), characterId)) {
				m_extras[i].m_unk0x14 = TRUE;
			}
			else {
				m_extras[i].m_unk0x14 = FALSE;
			}

			result = world->PlaceActor(actor, p_presenter, position, direction);
		}

		if (result != SUCCESS && g_characters[characterId].m_unk0x07) {
			result = world->PlaceActor(actor);
		}

		g_characters[characterId].m_unk0x07 = FALSE;

		if (result != SUCCESS) {
			m_extras[i].m_roi = NULL;
			g_characters[characterId].m_inExtras = FALSE;
		}
		else {
			m_extras[i].m_characterId = characterId;
			m_extras[i].m_unk0x08 = Timer()->GetTime();
			m_extras[i].m_unk0x0c = TRUE;
			m_extras[i].m_unk0x0d = FALSE;
			g_characters[characterId].m_inExtras = TRUE;
			actor->SetWorldSpeed(0.0f);
			m_unk0x414++;
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10063270
// FUNCTION: BETA10 0x10044b9a
void LegoAnimationManager::FUN_10063270(LegoROIList* p_list, LegoAnimPresenter* p_presenter)
{
	if (p_list != NULL) {
		LegoWorld* world = CurrentWorld();
		LegoROI* roi;
		MxU32 i;

		for (i = 0; i < sizeOfArray(g_vehicles); i++) {
			roi = Lego()->FindROI(g_vehicles[i].m_name);

			if (roi != NULL) {
				if (!g_vehicles[i].m_unk0x05 && roi->GetVisibility()) {
					g_vehicles[i].m_unk0x04 = TRUE;
				}
				else {
					g_vehicles[i].m_unk0x04 = FALSE;
				}
			}
		}

		LegoROIListCursor cursor(p_list);

		while (cursor.Next(roi)) {
			if (roi->GetVisibility() && FUN_10062e20(roi, p_presenter)) {
				cursor.Detach();
				FUN_10063950(roi);
			}
			else {
				LegoExtraActor* actor = CharacterManager()->GetExtraActor(roi->GetName());

				if (actor != NULL) {
					for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
						if (m_extras[i].m_roi == roi) {
							if (actor->GetController() != NULL) {
								actor->GetController()->RemoveActor(actor);
								actor->SetController(NULL);
							}

							if (m_extras[i].m_unk0x14) {
								m_extras[i].m_unk0x14 = FALSE;

								MxS32 vehicleId = g_characters[m_extras[i].m_characterId].m_vehicleId;
								if (vehicleId >= 0) {
									g_vehicles[vehicleId].m_unk0x05 = FALSE;

									LegoROI* roi = Lego()->FindROI(g_vehicles[vehicleId].m_name);
									if (roi != NULL) {
										roi->SetVisibility(FALSE);
									}
								}
							}

							m_extras[i].m_roi = NULL;
							g_characters[m_extras[i].m_characterId].m_inExtras = FALSE;
							g_characters[m_extras[i].m_characterId].m_unk0x07 = FALSE;
							m_extras[i].m_characterId = -1;
							m_extras[i].m_unk0x0d = FALSE;
							m_unk0x414--;
							break;
						}
					}
				}
			}
		}

		FUN_10063e40(p_presenter);

		for (i = 0; i < sizeOfArray(g_vehicles); i++) {
			if (!g_vehicles[i].m_unk0x05) {
				roi = Lego()->FindROI(g_vehicles[i].m_name);

				if (roi != NULL) {
					roi->SetVisibility(FALSE);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10063780
void LegoAnimationManager::FUN_10063780(LegoROIList* p_list)
{
	if (p_list != NULL && m_unk0x424 != NULL) {
		LegoROIListCursor cursor(p_list);
		LegoROI* roi;

		while (cursor.Next(roi)) {
			const char* name = roi->GetName();

			if (CharacterManager()->IsActor(name)) {
				m_unk0x424->Append(roi);
				cursor.Detach();
			}
		}
	}
}

// FUNCTION: LEGO1 0x10063950
void LegoAnimationManager::FUN_10063950(LegoROI* p_roi)
{
	if (m_unk0x424 != NULL) {
		LegoROIListCursor cursor(m_unk0x424);

		if (cursor.Find(p_roi)) {
			CharacterManager()->ReleaseActor(p_roi);
			cursor.Detach();
		}
	}
}

// FUNCTION: LEGO1 0x10063aa0
void LegoAnimationManager::FUN_10063aa0()
{
	LegoROIListCursor cursor(m_unk0x424);
	LegoROI* roi;

	while (cursor.Next(roi)) {
		CharacterManager()->ReleaseActor(roi);
	}
}

// FUNCTION: LEGO1 0x10063b90
// FUNCTION: BETA10 0x10044d46
MxBool LegoAnimationManager::FUN_10063b90(LegoWorld* p_world, LegoExtraActor* p_actor, MxU8 p_mood, MxU32 p_characterId)
{
	const char** cycles = g_cycles[g_characters[p_characterId].m_unk0x16];
	const char* vehicleWC;

	if (g_characters[p_characterId].m_vehicleId >= 0 && g_vehicles[g_characters[p_characterId].m_vehicleId].m_unk0x04 &&
		(vehicleWC = cycles[10]) != NULL) {
		LegoLocomotionAnimPresenter* presenter =
			(LegoLocomotionAnimPresenter*) p_world->Find("LegoAnimPresenter", vehicleWC);

		if (presenter != NULL) {
			presenter->FUN_1006d680(p_actor, 1.7f);
		}

		g_vehicles[g_characters[p_characterId].m_vehicleId].m_unk0x04 = FALSE;
		g_vehicles[g_characters[p_characterId].m_vehicleId].m_unk0x05 = TRUE;
		return TRUE;
	}
	else {
		vehicleWC = cycles[p_mood];
		if (vehicleWC != NULL) {
			LegoLocomotionAnimPresenter* presenter =
				(LegoLocomotionAnimPresenter*) p_world->Find("LegoAnimPresenter", vehicleWC);

			if (presenter != NULL) {
				presenter->FUN_1006d680(p_actor, 0.7f);
			}
		}

		if (p_mood >= 2) {
			p_mood--;
		}

		vehicleWC = cycles[p_mood + 4];
		if (vehicleWC != NULL) {
			LegoLocomotionAnimPresenter* presenter =
				(LegoLocomotionAnimPresenter*) p_world->Find("LegoAnimPresenter", vehicleWC);

			if (presenter != NULL) {
				presenter->FUN_1006d680(p_actor, 4.0f);
			}
		}

		if (p_mood >= 1) {
			p_mood--;
		}

		vehicleWC = cycles[p_mood + 7];
		if (vehicleWC != NULL) {
			LegoLocomotionAnimPresenter* presenter =
				(LegoLocomotionAnimPresenter*) p_world->Find("LegoAnimPresenter", vehicleWC);

			if (presenter != NULL) {
				presenter->FUN_1006d680(p_actor, 0.0f);
			}
		}

		return FALSE;
	}
}

// FUNCTION: LEGO1 0x10063d10
// FUNCTION: BETA10 0x10045034
void LegoAnimationManager::FUN_10063d10()
{
	if (CurrentWorld() != NULL) {
		MxLong time = Timer()->GetTime();

		for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
			LegoROI* roi = m_extras[i].m_roi;

			if (roi != NULL) {
				if (m_extras[i].m_unk0x0c && g_characters[m_extras[i].m_characterId].m_unk0x0c >= 0 &&
					g_characters[m_extras[i].m_characterId].m_unk0x0c < time - m_extras[i].m_unk0x08) {

					m_extras[i].m_unk0x0c = FALSE;

					LegoExtraActor* actor = CharacterManager()->GetExtraActor(roi->GetName());
					if (actor != NULL) {
						float speed = m_extras[i].m_speed;

						if (speed < 0.0f) {
							if (m_extras[i].m_unk0x14) {
								speed = ((float) (rand() * 1.5) / 32767.0f) + 0.9;
							}
							else {
								speed = ((float) (rand() * 1.4) / 32767.0f) + 0.6;
							}
						}

						actor->SetWorldSpeed(speed);
					}
				}
				else {
					LegoExtraActor* actor = CharacterManager()->GetExtraActor(roi->GetName());
					if (actor != NULL) {
						actor->Restart();
					}
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10063e40
void LegoAnimationManager::FUN_10063e40(LegoAnimPresenter* p_presenter)
{
	if (m_unk0x424 != NULL) {
		LegoROIListCursor cursor(m_unk0x424);
		LegoROI* roi;

		while (cursor.Next(roi)) {
			if (!FUN_10062e20(roi, p_presenter)) {
				CharacterManager()->ReleaseActor(roi);
			}

			cursor.Detach();
		}
	}
}

// FUNCTION: LEGO1 0x10063fb0
// FUNCTION: BETA10 0x100452a7
MxBool LegoAnimationManager::FUN_10063fb0(LegoLocation::Boundary* p_boundary, LegoWorld* p_world)
{
	if (p_boundary->m_name != NULL) {
		Mx3DPointFloat vec;
		LegoPathBoundary* boundary = p_world->FindPathBoundary(p_boundary->m_name);
		LegoUnknown100db7f4* pSrcE = (LegoUnknown100db7f4*) boundary->GetEdges()[p_boundary->m_src];
		return FUN_10064010(boundary, pSrcE, p_boundary->m_srcScale);
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10064010
// FUNCTION: BETA10 0x100453a5
MxBool LegoAnimationManager::FUN_10064010(LegoPathBoundary* p_boundary, LegoUnknown100db7f4* p_edge, float p_destScale)
{
	Mx3DPointFloat p1;
	Vector3* v1 = p_edge->CWVertex(*p_boundary);
	Vector3* v2 = p_edge->CCWVertex(*p_boundary);

	p1 = *v2;
	p1 -= *v1;
	p1 *= p_destScale;
	p1 += *v1;

	BoundingBox boundingBox;
	Mx3DPointFloat vec(1.0f, 1.0f, 1.0f);

	boundingBox.Min() = p1;
	boundingBox.Min() -= vec;
	boundingBox.Max() = p1;
	boundingBox.Max() += vec;
	return GetViewManager()->IsBoundingBoxInFrustum(boundingBox) == FALSE;
}

// FUNCTION: LEGO1 0x10064120
// FUNCTION: BETA10 0x100454f5
MxBool LegoAnimationManager::FUN_10064120(LegoLocation::Boundary* p_boundary, MxBool p_bool1, MxBool p_bool2)
{
	MxU32 local2c = 12;
	float destScale = ((rand() * 0.5) / 32767.0) + 0.25;
	LegoPathActor* actor = UserActor();

	if (actor == NULL) {
		return FALSE;
	}

	LegoPathBoundary* boundary = actor->GetBoundary();

	if (boundary == NULL) {
		return FALSE;
	}

	Mx3DPointFloat direction = actor->GetWorldDirection();
	float local4c = 0.0f;
	LegoUnknown100db7f4* local50 = NULL;
	LegoS32 numEdges = boundary->GetNumEdges();
	Mx3DPointFloat vec;
	LegoUnknown100db7f4* e;
	MxS32 i;

	for (i = 0; i < numEdges; i++) {
		e = (LegoUnknown100db7f4*) boundary->GetEdges()[i];
		e->FUN_1002ddc0(*boundary, vec);
		float dot = vec.Dot(&direction, &vec);

		if (dot > local4c) {
			local50 = e;
			local4c = dot;
		}
	}

	e = local50;
	do {
		e = (LegoUnknown100db7f4*) e->GetCounterclockwiseEdge(*boundary);
		if (e->GetMask0x03()) {
			break;
		}
	} while (e != local50);

	if (e == local50) {
		return FALSE;
	}

	LegoUnknown100db7f4* local34 = e;
	LegoUnknown100db7f4* local8 = local50;

	while (local2c--) {
		if (local34 != NULL) {
			if (local34->BETA_1004a830(*boundary, LegoWEGEdge::c_bit1) && FUN_10064010(boundary, local34, destScale) &&
				(!p_bool2 || FUN_10064010(boundary, local8, destScale))) {
				p_boundary->m_srcScale = p_boundary->m_destScale = destScale;
				p_boundary->m_name = boundary->GetName();
				numEdges = boundary->GetNumEdges();

				for (i = 0; i < numEdges; i++) {
					LegoUnknown100db7f4* e = (LegoUnknown100db7f4*) boundary->GetEdges()[i];

					if (local34 == e) {
						p_boundary->m_src = i;
					}
					else if (local8 == e) {
						p_boundary->m_dest = i;
					}
				}

				return TRUE;
			}

			local8 = local34;
			boundary = (LegoPathBoundary*) local34->OtherFace(boundary);
			local50 = local34;

			do {
				if (p_bool1) {
					local34 = (LegoUnknown100db7f4*) local34->GetCounterclockwiseEdge(*boundary);
				}
				else {
					local34 = (LegoUnknown100db7f4*) local34->GetClockwiseEdge(*boundary);
				}
			} while (!local34->GetMask0x03() && local34 != local50);

			if (local34 == local50) {
				return FALSE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10064380
// FUNCTION: BETA10 0x1004583a
MxResult LegoAnimationManager::FUN_10064380(
	const char* p_name,
	const char* p_boundaryName,
	MxS32 p_src,
	float p_srcScale,
	MxS32 p_dest,
	float p_destScale,
	MxU32 p_undIdx1,
	MxS32 p_unk0x0c,
	MxU32 p_undIdx2,
	MxS32 p_unk0x10,
	float p_speed
)
{
	LegoWorld* world = CurrentWorld();
	MxS32 extraIndex = -1;
	LegoExtraActor* actor = NULL;
	MxS32 i;

	for (i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
		LegoROI* roi = m_extras[i].m_roi;

		if (roi == NULL && extraIndex == -1) {
			extraIndex = i;
		}

		if (roi != NULL && !strcmpi(roi->GetName(), p_name)) {
			actor = CharacterManager()->GetExtraActor(p_name);

			if (actor != NULL && actor->GetController() != NULL) {
				actor->GetController()->RemoveActor(actor);
				actor->SetController(NULL);
				actor->ClearMaps();
			}

			break;
		}
	}

	if (actor == NULL && extraIndex != -1) {
		i = extraIndex;

		MxS32 characterId;
		for (characterId = 0; characterId < (MxS32) sizeOfArray(g_characters); characterId++) {
			if (!strcmpi(g_characters[characterId].m_name, p_name)) {
				break;
			}
		}

		if (characterId > sizeOfArray(g_characters)) {
			return FAILURE;
		}

		m_extras[extraIndex].m_roi = CharacterManager()->GetActorROI(p_name, TRUE);
		m_extras[extraIndex].m_characterId = characterId;
		m_extras[extraIndex].m_speed = p_speed;

		actor = CharacterManager()->GetExtraActor(p_name);
		m_unk0x414++;
	}

	if (actor != NULL) {
		MxU8 unk0x0c = rand() % 2 != 0 ? 1 : 2;
		actor->SetUnknown0x0c(unk0x0c);
		actor->SetWorldSpeed(0.0f);

		if (world->PlaceActor(actor, p_boundaryName, p_src, p_srcScale, p_dest, p_destScale) != SUCCESS) {
			CharacterManager()->ReleaseActor(m_extras[i].m_roi);
			m_extras[i].m_roi = NULL;
			m_unk0x414--;
			return FAILURE;
		}

		MxS32 characterId = m_extras[i].m_characterId;
		const char** cycles = g_cycles[g_characters[characterId].m_unk0x16];

		LegoLocomotionAnimPresenter* presenter =
			(LegoLocomotionAnimPresenter*) world->Find("LegoAnimPresenter", cycles[p_undIdx1]);
		if (presenter != NULL) {
			presenter->FUN_1006d680(actor, 0.0f);
		}

		presenter = (LegoLocomotionAnimPresenter*) world->Find("LegoAnimPresenter", cycles[p_undIdx2]);
		if (presenter != NULL) {
			presenter->FUN_1006d680(actor, 4.0f);
		}

		m_extras[i].m_unk0x08 = Timer()->GetTime();
		m_extras[i].m_unk0x0c = TRUE;
		m_extras[i].m_speed = p_speed;

		g_characters[characterId].m_unk0x0c = p_unk0x0c;
		g_characters[characterId].m_unk0x10 = p_unk0x10;
		g_characters[characterId].m_inExtras = TRUE;
		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x10064670
MxResult LegoAnimationManager::FUN_10064670(Vector3* p_position)
{
	MxBool success = FALSE;

	if (p_position != NULL) {
		Mx3DPointFloat vec(98.875f, 0.0f, -46.1564f);
		vec -= *p_position;

		if (vec.LenSquared() < 800.0f) {
			success = TRUE;
		}
	}
	else {
		success = TRUE;
	}

	if (success) {
		return FUN_10064380("brickstr", "EDG02_95", 1, 0.5f, 3, 0.5f, rand() % 3 + 14, -1, rand() % 3, -1, 0.5f);
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x10064740
MxResult LegoAnimationManager::FUN_10064740(Vector3* p_position)
{
	MxBool success = FALSE;

	if (p_position != NULL) {
		Mx3DPointFloat vec(-21.375f, 0.0f, -41.75f);
		vec -= *p_position;

		if (vec.LenSquared() < 1000.0f) {
			success = TRUE;
		}
	}
	else {
		success = TRUE;
	}

	if (success) {
		if (GameState()->GetActorId() != LegoActor::c_mama) {
			FUN_10064380("mama", "USR00_47", 1, 0.43f, 3, 0.84f, rand() % 3 + 13, -1, rand() % 3, -1, 0.7f);
		}

		if (GameState()->GetActorId() != LegoActor::c_papa) {
			FUN_10064380("papa", "USR00_193", 3, 0.55f, 1, 0.4f, rand() % 3 + 13, -1, rand() % 3, -1, 0.9f);
		}

		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x10064880
// FUNCTION: BETA10 0x10045d02
MxResult LegoAnimationManager::FUN_10064880(const char* p_name, MxS32 p_unk0x0c, MxS32 p_unk0x10)
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_extras); i++) {
		LegoROI* roi = m_extras[i].m_roi;

		if (roi != NULL) {
			if (!strcmpi(roi->GetName(), p_name)) {
				g_characters[m_extras[i].m_characterId].m_unk0x0c = p_unk0x0c;
				g_characters[m_extras[i].m_characterId].m_unk0x10 = p_unk0x10;
				return SUCCESS;
			}
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100648f0
// FUNCTION: BETA10 0x10045daf
void LegoAnimationManager::FUN_100648f0(LegoTranInfo* p_tranInfo, MxLong p_unk0x404)
{
	if (m_unk0x402 && p_tranInfo->m_unk0x14) {
		p_tranInfo->m_flags |= LegoTranInfo::c_bit1;
		m_unk0x430 = TRUE;
		m_unk0x42c = p_tranInfo;
		m_unk0x434 = p_unk0x404;
		m_unk0x438 = p_unk0x404 + 1000;

		ViewROI* viewROI = VideoManager()->GetViewROI();
		m_unk0x43c = viewROI->GetLocal2World();
		p_tranInfo->m_unk0x2c = m_unk0x43c;

		LegoPathActor* actor = UserActor();
		if (actor != NULL) {
			actor->SetActorState(LegoPathActor::c_disabled);
			actor->SetWorldSpeed(0.0f);
		}

		LegoLocation* location = NavController()->GetLocation(p_tranInfo->m_location);
		if (location != NULL) {
			CalcLocalTransform(location->m_position, location->m_direction, location->m_up, m_unk0x484);
			m_unk0x4cc.BETA_1004a9b0(m_unk0x43c, m_unk0x484);
			m_unk0x4cc.FUN_10004520();
		}
		else {
			p_tranInfo->m_flags &= ~LegoTranInfo::c_bit1;
			m_unk0x430 = FALSE;
		}

		Mx3DPointFloat vec;
		vec.Clear();
		viewROI->FUN_100a5a30(vec);
	}
}

// FUNCTION: LEGO1 0x10064b50
// FUNCTION: BETA10 0x10045f14
void LegoAnimationManager::FUN_10064b50(MxLong p_time)
{
	if (m_unk0x430 && m_unk0x42c != NULL) {
		MxMatrix mat;

		if (p_time < 0 || m_unk0x438 <= p_time) {
			m_unk0x430 = FALSE;
			m_unk0x42c->m_flags &= ~LegoTranInfo::c_bit1;
			m_unk0x42c = NULL;
			mat = m_unk0x484;
		}
		else {
			float und = (float) (p_time - m_unk0x434) / (float) (m_unk0x438 - m_unk0x434);

			float sub[3];
			sub[0] = (m_unk0x484[3][0] - m_unk0x43c[3][0]) * und;
			sub[1] = (m_unk0x484[3][1] - m_unk0x43c[3][1]) * und;
			sub[2] = (m_unk0x484[3][2] - m_unk0x43c[3][2]) * und;

			m_unk0x4cc.BETA_1004aaa0(mat, (float) (p_time - m_unk0x434) / 1000.0f);

			VPV3(mat[3], m_unk0x43c[3], sub);
			mat[3][3] = 1.0f;
		}

		LegoROI* viewROI = VideoManager()->GetViewROI();

		viewROI->WrappedSetLocalTransform(mat);
		VideoManager()->Get3DManager()->Moved(*viewROI);
		SoundManager()->UpdateListener(
			viewROI->GetWorldPosition(),
			viewROI->GetWorldDirection(),
			viewROI->GetWorldUp(),
			viewROI->GetWorldVelocity()
		);
	}
}

// FUNCTION: LEGO1 0x10064ee0
MxBool LegoAnimationManager::FUN_10064ee0(MxU32 p_objectId)
{
	if (m_tranInfoList != NULL) {
		LegoTranInfoListCursor cursor(m_tranInfoList);
		LegoTranInfo* tranInfo;

		while (cursor.Next(tranInfo)) {
			if (tranInfo->m_animInfo->m_objectId == p_objectId) {
				if (tranInfo->m_presenter) {
					return tranInfo->m_presenter->FUN_1004b830();
				}
				else {
					return FALSE;
				}
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10064ff0
AnimState::AnimState()
{
	m_unk0x0c = 0;
	m_unk0x10 = NULL;
	m_locationsFlagsLength = 0;
	m_locationsFlags = NULL;
}

// FUNCTION: LEGO1 0x10065150
AnimState::~AnimState()
{
	delete[] m_unk0x10;
	delete[] m_locationsFlags;
}

// FUNCTION: LEGO1 0x100651d0
void AnimState::CopyToAnims(MxU32, AnimInfo* p_anims, MxU32& p_outExtraCharacterId)
{
	if (m_unk0x10 != NULL) {
		for (MxS32 i = 0; i < m_unk0x0c; i++) {
			p_anims[i].m_unk0x22 = m_unk0x10[i];
		}

		p_outExtraCharacterId = m_extraCharacterId;

		for (MxS32 j = 0; j < m_locationsFlagsLength; j++) {
			LegoLocation* location = LegoNavController::GetLocation(j);
			if (location != NULL) {
				location->m_unk0x5c = m_locationsFlags[j];
			}
		}
	}
}

// FUNCTION: LEGO1 0x10065240
void AnimState::InitFromAnims(MxU32 p_animsLength, AnimInfo* p_anims, MxU32 p_extraCharacterId)
{
	if (m_unk0x10 == NULL) {
		m_unk0x0c = p_animsLength;
		m_unk0x10 = new MxU16[p_animsLength];
		MxS32 numLocations = LegoNavController::GetNumLocations();
		m_locationsFlagsLength = numLocations;
		m_locationsFlags = new MxBool[numLocations];
	}

	m_extraCharacterId = p_extraCharacterId;

	for (MxS32 i = 0; i < m_unk0x0c; i++) {
		m_unk0x10[i] = p_anims[i].m_unk0x22;
	}

	for (MxS32 j = 0; j < m_locationsFlagsLength; j++) {
		LegoLocation* location = LegoNavController::GetLocation(j);
		if (location != NULL) {
			m_locationsFlags[j] = location->m_unk0x5c;
		}
	}
}

// FUNCTION: LEGO1 0x100652d0
// FUNCTION: BETA10 0x10046621
MxResult AnimState::Serialize(LegoFile* p_file)
{
	// These two are equivalent up to the order of some deallocation.
	// Choose as needed to get 100 %.
	// Option 1:
	// LegoState::Serialize(p_file);
	// Option 2:
	if (p_file->IsWriteMode()) {
		p_file->WriteString(ClassName());
	}

	if (p_file->IsReadMode()) {
		Read(p_file, &m_extraCharacterId);

		if (m_unk0x10) {
			delete[] m_unk0x10;
		}

		Read(p_file, &m_unk0x0c);
		if (m_unk0x0c != 0) {
			m_unk0x10 = new MxU16[m_unk0x0c];
		}
		else {
			m_unk0x10 = NULL;
		}

		for (MxS32 i = 0; i < m_unk0x0c; i++) {
			Read(p_file, &m_unk0x10[i]);
		}

		// Note that here we read first and then free memory in contrast to above
		Read(p_file, &m_locationsFlagsLength);

		if (m_locationsFlags) {
			delete[] m_locationsFlags;
		}

		if (m_locationsFlagsLength != 0) {
			m_locationsFlags = new MxBool[m_locationsFlagsLength];
		}
		else {
			m_locationsFlags = NULL;
		}

		for (MxS32 j = 0; j < m_locationsFlagsLength; j++) {
			Read(p_file, &m_locationsFlags[j]);
		}
	}
	else if (p_file->IsWriteMode()) {
		Write(p_file, m_extraCharacterId);

		Write(p_file, m_unk0x0c);
		for (MxS32 i = 0; i < m_unk0x0c; i++) {
			Write(p_file, m_unk0x10[i]);
		}

		Write(p_file, m_locationsFlagsLength);
		for (MxS32 j = 0; j < m_locationsFlagsLength; j++) {
			Write(p_file, m_locationsFlags[j]);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100654f0
MxBool AnimState::Reset()
{
	if (m_unk0x10 != NULL) {
		m_extraCharacterId = 0;

		for (MxS32 i = 0; i < m_unk0x0c; i++) {
			m_unk0x10[i] = 0;
		}

		for (MxS32 j = 0; j < m_locationsFlagsLength; j++) {
			if (LegoNavController::GetLocation(j) != NULL) {
				m_locationsFlags[j] = 0;
			}
		}

		return TRUE;
	}

	return FALSE;
}
