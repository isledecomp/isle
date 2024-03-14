#include "legoanimationmanager.h"

#include "legogamestate.h"
#include "legoomni.h"
#include "misc.h"
#include "mxutilities.h"

#include <io.h>

DECOMP_SIZE_ASSERT(LegoAnimationManager, 0x500)

// GLOBAL: LEGO1 0x100f7048
Character g_characters[47]; // TODO: Initialize this

// GLOBAL: LEGO1 0x100f74f8
int g_legoAnimationManagerConfig = 1;

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

// FUNCTION: LEGO1 0x1005f720
MxResult LegoAnimationManager::LoadScriptInfo(MxS32 p_scriptIndex)
{
	MxResult result = FAILURE;
	if (m_unk0x08 != p_scriptIndex) {
		if (m_tranInfoList != NULL) {
			delete m_tranInfoList;
			m_tranInfoList = NULL;
		}
		if (m_tranInfoList2 != NULL) {
			delete m_tranInfoList2;
			m_tranInfoList2 = NULL;
		}
		for (int i = 0; i < 2; i++) {
			m_unk0x28[i] = 0;
			m_unk0x30[i] = 0;
		}
		m_unk0x38 = 0;
		m_unk0x39 = 0;
		m_unk0x430 = 0;
		m_unk0x42c = 0;
		for (int i2 = 0; i2 < 0x2f; i2++) {
			g_characters[i2].m_active = FALSE;
		}
		m_animState = (AnimState*) GameState()->GetState("AnimState");
		if (m_animState == NULL) {
			m_animState = (AnimState*) GameState()->CreateState("AnimState");
		}
		if (m_unk0x08 == 0) {
			m_animState->FUN_10065240(m_animCount, m_anims, m_unk0x3fc);
		}
		FUN_100603c0();
		LegoFile file;
		if (p_scriptIndex == -1) {
			result = SUCCESS;
		}
		else {
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
			if (file.Read(&version, 4) == FAILURE) {
				goto done;
			}
			if (version != 3) {
				OmniError("World animation version mismatch", 0);
				goto done;
			}
			if (file.Read(&m_animCount, 2) == FAILURE) {
				goto done;
			}
			m_anims = new AnimInfo[m_animCount];
			memset(m_anims, 0, m_animCount * sizeof(AnimInfo));
			for (int i = 0; i < m_animCount; i++) {
				if (ReadAnimInfo(&file, &m_anims[i]) == FAILURE) {
					goto done;
				}
				m_anims[i].m_unk0x28 = FUN_10062360(m_anims[i].m_animName + strlen(m_anims[i].m_animName) - 2);
				m_anims[i].m_unk0x29 = 0;
				for (int j = 0; j < 3; j++) {
					m_anims[i].m_unk0x2a[j] = -1;
				}
				if (m_anims[i].m_unk0x08 == -1) {
					for (int j = 0; j < m_anims[i].m_modelCount; j++) {
						MxS32 index = FUN_10062360(m_anims[i].m_models[j].m_modelName);
						if (index >= 0) {
							g_characters[index].m_active = TRUE;
						}
					}
				}
				MxS32 count = 0;
				for (int j2 = 0; j2 < m_anims[i].m_modelCount; j2++) {
					MxU32 k;
					if (FUN_10060140(m_anims[i].m_models[j2].m_modelName, k) && m_anims[i].m_models[j2].m_unk0x2c) {
						m_anims[i].m_unk0x2a[count++] = k;
						if (count > 3) {
							break;
						}
					}
				}
			}
			m_unk0x08 = p_scriptIndex;
			m_tranInfoList = new LegoUnknown100d8c90();
			m_tranInfoList2 = new LegoUnknown100d8c90();
			FUN_100617c0(-1, m_unk0x0e, m_unk0x10);
			result = SUCCESS;
			m_unk0x402 = 1;
			if (m_unk0x42b) {
				m_unk0x42a = 1;
				m_unk0x402 = 0;
				m_unk0x428 = m_unk0x3a;
				m_unk0x3a = 0;
				m_unk0x429 = m_unk0x400;
				m_unk0x400 = 0;
			}
			if (p_scriptIndex == 0) {
				m_animState->FUN_100651d0(m_animCount, m_anims, m_unk0x3fc);
			}
		}
	}
done:
	if (result == FAILURE) {
		FUN_100603c0();
	}
	return result;
}

// FUNCTION: LEGO1 0x1005fe50
void LegoUnknown100d8ca8Handler()
{
}

void LegoUnknown100d8cd8Handler()
{
}

// STUB: LEGO1 0x10060140
MxBool LegoAnimationManager::FUN_10060140(char* p_name, MxU32& p_index)
{
	return FALSE;
}

// FUNCTION: LEGO1 0x10060180
MxResult LegoAnimationManager::ReadAnimInfo(LegoFile* p_file, AnimInfo* p_info)
{
	MxResult result = FAILURE;
	MxU8 length;
	int i, i2;
	if (p_file->Read(&length, 1) == FAILURE) {
		goto fail;
	}
	p_info->m_animName = new char[length + 1];
	if (p_file->Read(p_info->m_animName, length) == FAILURE) {
		goto fail;
	}
	p_info->m_animName[length] = 0;
	if (p_file->Read(&p_info->m_unk0x04, 4) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x08, 2) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x0a, 1) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x0b, 1) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x0c, 1) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x0d, 1) == FAILURE) {
		goto fail;
	}
	for (i = 0; i < 4; i++) {
		if (p_file->Read(&p_info->m_unk0x10[i], 4) != SUCCESS) {
			goto fail;
		}
	}
	if (p_file->Read(&p_info->m_modelCount, 1) == FAILURE) {
		goto fail;
	}
	p_info->m_models = new ModelInfo[p_info->m_modelCount];
	memset(p_info->m_models, 0, p_info->m_modelCount * sizeof(ModelInfo));
	for (i2 = 0; i2 < p_info->m_modelCount; i2++) {
		if (ReadModelInfo(p_file, &p_info->m_models[i2]) == FAILURE) {
			goto fail;
		}
	}
	result = SUCCESS;
fail:
	return result;
}

// FUNCTION: LEGO1 0x10060310
MxResult LegoAnimationManager::ReadModelInfo(LegoFile* p_file, ModelInfo* p_info)
{
	MxResult result = FAILURE;
	MxU8 length;
	if (p_file->Read(&length, 1) == FAILURE) {
		goto fail;
	}
	p_info->m_modelName = new char[length + 1];
	if (p_file->Read(p_info->m_modelName, length) == FAILURE) {
		goto fail;
	}
	p_info->m_modelName[length] = 0;
	if (p_file->Read(&p_info->m_unk0x04, 1) == FAILURE) {
		goto fail;
	}
	if (p_file->Read(p_info->m_location, 12) != SUCCESS) {
		goto fail;
	}
	if (p_file->Read(p_info->m_direction, 12) != SUCCESS) {
		goto fail;
	}
	if (p_file->Read(p_info->m_up, 12) != SUCCESS) {
		goto fail;
	}
	if (p_file->Read(&p_info->m_unk0x2c, 1) == FAILURE) {
		goto fail;
	}
	result = SUCCESS;
fail:
	return result;
}

// STUB: LEGO1 0x100603c0
void LegoAnimationManager::FUN_100603c0()
{
}

// STUB: LEGO1 0x10061010
void LegoAnimationManager::FUN_10061010(undefined4)
{
	// TODO
}

// STUB: LEGO1 0x100617c0
void LegoAnimationManager::FUN_100617c0(MxS32, MxU16&, MxU32&)
{
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
	return 0;
}

// STUB: LEGO1 0x10064670
void LegoAnimationManager::FUN_10064670(MxBool)
{
}
