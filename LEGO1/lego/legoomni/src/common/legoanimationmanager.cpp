#include "legoanimationmanager.h"

#include "legocharactermanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "misc.h"
#include "mxutilities.h"
#include "roi/legoroi.h"

#include <io.h>

DECOMP_SIZE_ASSERT(LegoAnimationManager, 0x500)
DECOMP_SIZE_ASSERT(Character, 0x18)
DECOMP_SIZE_ASSERT(Vehicle, 0x8)
DECOMP_SIZE_ASSERT(Unknown0x3c, 0x18)

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

// GLOBAL: LEGO1 0x100f74f8
MxS32 g_legoAnimationManagerConfig = 1;

// FUNCTION: LEGO1 0x1005eb50
void LegoAnimationManager::configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig)
{
	g_legoAnimationManagerConfig = p_legoAnimationManagerConfig;
}

// STUB: LEGO1 0x1005eb60
LegoAnimationManager::LegoAnimationManager()
{
	// TODO
}

// STUB: LEGO1 0x1005ed30
LegoAnimationManager::~LegoAnimationManager()
{
	// TODO
}

// STUB: LEGO1 0x1005ee80
void LegoAnimationManager::FUN_1005ee80(MxBool)
{
	// TODO
}

// STUB: LEGO1 0x1005ef10
void LegoAnimationManager::FUN_1005ef10()
{
	// TODO
}

// STUB: LEGO1 0x1005f0b0
void LegoAnimationManager::FUN_1005f0b0()
{
	// TODO
}

// STUB: LEGO1 0x1005f130
void LegoAnimationManager::Init()
{
	// TODO
}

// STUB: LEGO1 0x1005f6d0
void LegoAnimationManager::FUN_1005f6d0(MxBool)
{
	// TODO
}

// STUB: LEGO1 0x1005f700
void LegoAnimationManager::FUN_1005f700(MxBool)
{
	// TODO
}

// FUNCTION: LEGO1 0x1005f720
MxResult LegoAnimationManager::LoadScriptInfo(MxS32 p_scriptIndex)
{
	MxResult result = FAILURE;
	MxS32 i, j, k;

	if (m_unk0x08 != p_scriptIndex) {
		if (m_tranInfoList != NULL) {
			delete m_tranInfoList;
			m_tranInfoList = NULL;
		}

		if (m_tranInfoList2 != NULL) {
			delete m_tranInfoList2;
			m_tranInfoList2 = NULL;
		}

		for (i = 0; i < (MxS32) _countof(m_unk0x28); i++) {
			m_unk0x28[i] = 0;
			m_unk0x30[i] = 0;
		}

		m_unk0x38 = 0;
		m_unk0x39 = 0;
		m_unk0x430 = 0;
		m_unk0x42c = 0;

		for (j = 0; j < (MxS32) _countof(g_characters); j++) {
			g_characters[j].m_active = FALSE;
		}

		m_animState = (AnimState*) GameState()->GetState("AnimState");
		if (m_animState == NULL) {
			m_animState = (AnimState*) GameState()->CreateState("AnimState");
		}

		if (m_unk0x08 == 0) {
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
		sprintf(filename, "lego\\data\\%sinf.dta", Lego()->FindScript(p_scriptIndex));
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

			m_anims[j].m_unk0x28 = FUN_10062360(m_anims[j].m_animName + strlen(m_anims[j].m_animName) - 2);
			m_anims[j].m_unk0x29 = 0;

			for (k = 0; k < 3; k++) {
				m_anims[j].m_unk0x2a[k] = -1;
			}

			if (m_anims[j].m_unk0x08 == -1) {
				for (MxS32 l = 0; l < m_anims[j].m_modelCount; l++) {
					MxS32 index = FUN_10062360(m_anims[j].m_models[l].m_modelName);

					if (index >= 0) {
						g_characters[index].m_active = TRUE;
					}
				}
			}

			MxS32 count = 0;
			for (MxS32 m = 0; m < m_anims[j].m_modelCount; m++) {
				MxU32 n;

				if (FindVehicle(m_anims[j].m_models[m].m_modelName, n) && m_anims[j].m_models[m].m_unk0x2c) {
					m_anims[j].m_unk0x2a[count++] = n;
					if (count > 3) {
						break;
					}
				}
			}
		}

		m_unk0x08 = p_scriptIndex;
		m_tranInfoList = new LegoTranInfoList();
		m_tranInfoList2 = new LegoTranInfoList();

		FUN_100617c0(-1, m_unk0x0e, m_unk0x10);

		result = SUCCESS;
		m_unk0x402 = 1;

		if (m_unk0x42b) {
			m_unk0x428 = m_unk0x3a;
			m_unk0x429 = m_unk0x400;
			m_unk0x42a = 1;
			m_unk0x3a = 0;
			m_unk0x400 = 0;
			m_unk0x402 = 0;
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

	p_info->m_animName = new char[length + 1];
	if (p_file->Read(p_info->m_animName, length) == FAILURE) {
		goto done;
	}

	p_info->m_animName[length] = 0;
	if (p_file->Read(&p_info->m_unk0x04, sizeof(p_info->m_unk0x04)) == FAILURE) {
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

	p_info->m_modelName = new char[length + 1];
	if (p_file->Read(p_info->m_modelName, length) == FAILURE) {
		goto done;
	}

	p_info->m_modelName[length] = 0;
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
	undefined unk0x42b = m_unk0x42b;

	if (m_anims != NULL) {
		for (MxS32 i = 0; i < m_animCount; i++) {
			delete m_anims[i].m_animName;

			if (m_anims[i].m_models != NULL) {
				for (MxS32 j = 0; j < m_anims[i].m_modelCount; j++) {
					delete m_anims[i].m_models[j].m_modelName;
				}

				delete m_anims[i].m_models;
			}
		}

		delete m_anims;
	}

	Init();
	m_unk0x42b = unk0x42b;
}

// STUB: LEGO1 0x10060570
void LegoAnimationManager::FUN_10060570(MxBool)
{
	// TODO
}

// FUNCTION: LEGO1 0x10060d00
MxResult LegoAnimationManager::StartEntityAction(MxDSAction& p_dsAction, LegoEntity* p_entity)
{
	MxResult result = FAILURE;
	LegoROI* roi = p_entity->GetROI();

	if (p_entity->GetUnknown0x59() == 0) {
		LegoPathActor* actor = CharacterManager()->GetActor(roi->GetName());

		if (actor) {
			LegoPathController* controller = actor->GetController();

			if (controller) {
				controller->FUN_10046770(actor);
				actor->ClearController();

				for (MxS32 i = 0; i < (MxS32) _countof(m_unk0x3c); i++) {
					if (m_unk0x3c[i].m_roi == roi) {
						MxU32 characterId = m_unk0x3c[i].m_id;
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

	if (StartActionIfUnknown0x13c(p_dsAction) == SUCCESS) {
		result = SUCCESS;
	}

	return result;
}

// STUB: LEGO1 0x10060dc0
undefined4 LegoAnimationManager::FUN_10060dc0(
	IsleScript::Script,
	undefined4,
	undefined,
	undefined,
	undefined4,
	undefined,
	undefined,
	undefined,
	undefined
)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10061010
void LegoAnimationManager::FUN_10061010(undefined4)
{
	// TODO
}

// STUB: LEGO1 0x100617c0
void LegoAnimationManager::FUN_100617c0(MxS32, MxU16&, MxU32&)
{
	// TODO
}

// STUB: LEGO1 0x100619f0
MxLong LegoAnimationManager::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10061cc0
MxResult LegoAnimationManager::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10062360
MxS8 LegoAnimationManager::FUN_10062360(char*)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100629b0
void LegoAnimationManager::FUN_100629b0(MxU32, MxBool)
{
	// TODO
}

// STUB: LEGO1 0x10064670
void LegoAnimationManager::FUN_10064670(MxBool)
{
	// TODO
}

// STUB: LEGO1 0x10064740
void LegoAnimationManager::FUN_10064740(MxBool)
{
	// TODO
}
