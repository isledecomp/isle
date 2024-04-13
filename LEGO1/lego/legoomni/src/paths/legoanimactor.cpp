#include "legoanimactor.h"

#include "define.h"
#include "legoanimpresenter.h"
#include "legoworld.h"
#include "misc.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoAnimActor, 0x174)
DECOMP_SIZE_ASSERT(LegoAnimActorStruct, 0x20)

// FUNCTION: LEGO1 0x1001bf80
LegoAnimActorStruct::LegoAnimActorStruct(float p_unk0x00, LegoAnim* p_AnimTreePtr, LegoROI** p_roiMap, MxU32 p_numROIs)
{
	m_unk0x00 = p_unk0x00;
	m_AnimTreePtr = p_AnimTreePtr;
	m_roiMap = p_roiMap;
	m_numROIs = p_numROIs;
}

// FUNCTION: LEGO1 0x1001c0a0
LegoAnimActorStruct::~LegoAnimActorStruct()
{
	for (MxU16 i = 0; i < m_unk0x10.size(); i++) {
		delete m_unk0x10[i];
	}
}

// FUNCTION: LEGO1 0x1001c130
float LegoAnimActorStruct::GetDuration()
{
	return m_AnimTreePtr->GetDuration();
}

// FUNCTION: LEGO1 0x1001c140
LegoAnimActor::~LegoAnimActor()
{
	for (MxS32 i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]) {
			delete m_animMaps[i];
		}
	}
}

// FUNCTION: LEGO1 0x1001c1f0
MxResult LegoAnimActor::FUN_1001c1f0(float& p_und)
{
	float duration = (float) m_animMaps[m_curAnim]->m_AnimTreePtr->GetDuration();
	p_und = m_actorTime - duration * ((MxS32) (m_actorTime / duration));
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001c240
void LegoAnimActor::VTable0x74(Matrix4& p_transform)
{
	float und;
	LegoPathActor::VTable0x74(p_transform);

	if (m_curAnim >= 0) {
		FUN_1001c1f0(und);
		FUN_1001c360(und, p_transform);
	}
}

// FUNCTION: LEGO1 0x1001c290
void LegoAnimActor::VTable0x70(float p_float)
{
	if (m_lastTime == 0) {
		m_lastTime = p_float - 1.0f;
	}

	if (m_state == 0 && !m_userNavFlag && m_worldSpeed <= 0) {
		if (m_curAnim >= 0) {
			MxMatrix matrix(m_unk0xec);
			float f;
			FUN_1001c1f0(f);
			FUN_1001c360(f, matrix);
		}

		m_lastTime = m_actorTime = p_float;
	}
	else {
		LegoPathActor::VTable0x70(p_float);
	}
}

// FUNCTION: LEGO1 0x1001c360
MxResult LegoAnimActor::FUN_1001c360(float p_und, Matrix4& p_transform)
{
	if (p_und >= 0) {
		LegoROI** roiMap = m_animMaps[m_curAnim]->m_roiMap;
		MxU32 numROIs = m_animMaps[m_curAnim]->m_numROIs;

		if (!m_boundary->GetFlag0x10()) {
			MxU32 i;
			m_roi->SetVisibility(FALSE);

			for (i = 0; i < numROIs; i++) {
				LegoROI* roi = roiMap[i];

				if (roi != NULL && m_roi != roi) {
					roi->SetVisibility(FALSE);
				}
			}
		}
		else {
			LegoTreeNode* root = m_animMaps[m_curAnim]->m_AnimTreePtr->GetRoot();
			m_roi->SetVisibility(TRUE);

			for (MxU32 i = 0; i < numROIs; i++) {
				LegoROI* roi = roiMap[i];

				if (roi != NULL && m_roi != roi) {
					roi->SetVisibility(TRUE);
				}
			}

			for (MxS32 j = 0; j < root->GetNumChildren(); j++) {
				LegoROI::FUN_100a8e80(root->GetChild(j), p_transform, p_und, roiMap);
			}

			if (m_cameraFlag) {
				FUN_10010c30();
			}
		}

		return SUCCESS;
	}
	else {
		return FAILURE;
	}
}

// FUNCTION: LEGO1 0x1001c450
MxResult LegoAnimActor::FUN_1001c450(LegoAnim* p_animTreePtr, float p_unk0x00, LegoROI** p_roiMap, MxU32 p_numROIs)
{
	LegoAnimActorStruct* laas = new LegoAnimActorStruct(p_unk0x00, p_animTreePtr, p_roiMap, p_numROIs);

	for (vector<LegoAnimActorStruct*>::iterator it = m_animMaps.begin(); it != m_animMaps.end(); it++) {
		if (p_unk0x00 < (*it)->m_unk0x00) {
			m_animMaps.insert(it, laas);
			SetWorldSpeed(m_worldSpeed);
			return SUCCESS;
		}
	}

	m_animMaps.push_back(laas);
	SetWorldSpeed(m_worldSpeed);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001c800
void LegoAnimActor::ClearMaps()
{
	for (MxU32 i = 0; i < m_animMaps.size(); i++) {
		delete m_animMaps[i];
	}

	m_animMaps.clear();
	m_curAnim = -1;
}

// FUNCTION: LEGO1 0x1001c870
void LegoAnimActor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (p_worldSpeed < 0) {
		m_worldSpeed = 0;
	}
	else {
		m_worldSpeed = p_worldSpeed;
	}

	if (m_animMaps.size() > 0) {
		m_curAnim = 0;

		if (m_worldSpeed >= m_animMaps[m_animMaps.size() - 1]->m_unk0x00) {
			m_curAnim = m_animMaps.size() - 1;
		}
		else {
			for (MxU32 i = 0; i < m_animMaps.size(); i++) {
				if (m_worldSpeed <= m_animMaps[i]->m_unk0x00) {
					m_curAnim = i;
					break;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x1001c920
void LegoAnimActor::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	LegoWorld* world = CurrentWorld();
	char value[256];

	if (world) {
		if (KeyValueStringParse(value, g_strANIMATION, p_extra)) {
			char* token = strtok(value, g_parseExtraTokens);

			while (token) {
				LegoAnimPresenter* presenter = (LegoAnimPresenter*) world->Find("LegoAnimPresenter", token);

				if (presenter != NULL) {
					token = strtok(NULL, g_parseExtraTokens);

					if (token) {
						presenter->FUN_1006d680(this, atof(token));
					}
				}

				token = strtok(NULL, g_parseExtraTokens);
			}
		}
	}
}
