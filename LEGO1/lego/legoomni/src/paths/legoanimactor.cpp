#include "legoanimactor.h"

#include "define.h"
#include "legoanimpresenter.h"
#include "legoworld.h"
#include "misc.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoAnimActor, 0x174)
DECOMP_SIZE_ASSERT(LegoAnimActorStruct, 0x20)

// FUNCTION: LEGO1 0x1001bf80
LegoAnimActorStruct::LegoAnimActorStruct(float p_float, LegoAnim* p_animTreePtr, LegoROI** p_roiMap, MxU32 p_numROIs)
{
	m_unk0x00 = p_float;
	m_animTreePtr = p_animTreePtr;
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
	return m_animTreePtr->GetDuration();
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
MxResult LegoAnimActor::FUN_1001c1f0(float& p_out)
{
	p_out = m_unk0x80 - (float) m_animMaps[m_curAnim]->m_animTreePtr->GetDuration() *
							((int) (m_unk0x80 / (float) m_animMaps[m_curAnim]->m_animTreePtr->GetDuration()));
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001c240
void LegoAnimActor::VTable0x74(Matrix4& p_transform)
{
	float f;
	LegoPathActor::VTable0x74(p_transform);
	if (m_curAnim >= 0) {
		FUN_1001c1f0(f);
		FUN_1001c360(f, p_transform);
	}
}

// FUNCTION: LEGO1 0x1001c290
void LegoAnimActor::VTable0x70(float p_float)
{
	if (m_unk0x84 == 0) {
		m_unk0x84 = p_float - 1.0f;
	}
	if (m_unk0xdc == 0 && !m_userNavFlag && m_worldSpeed <= 0) {
		if (m_curAnim >= 0) {
			MxMatrix matrix(m_unk0xec);
			float f;
			FUN_1001c1f0(f);
			FUN_1001c360(f, matrix);
		}
		m_unk0x84 = m_unk0x80 = p_float;
	}
	else {
		LegoPathActor::VTable0x70(p_float);
	}
}

// FUNCTION: LEGO1 0x1001c360
MxResult LegoAnimActor::FUN_1001c360(float p_float, Matrix4& p_transform)
{
	if (p_float >= 0) {
		LegoAnimActorStruct* anim = m_animMaps[m_curAnim];
		LegoROI** roiMap = anim->m_roiMap;
		MxU32 numROIs = anim->m_numROIs;
		if (m_boundary->GetFlag0x10()) {
			LegoTreeNode* root = anim->m_animTreePtr->GetRoot();
			m_roi->SetVisibility(TRUE);
			for (MxU32 i = 0; i < numROIs; i++) {
				if (roiMap[i] && (roiMap[i] != m_roi)) {
					roiMap[i]->SetVisibility(TRUE);
				}
			}
			for (MxU32 childIdx = 0; childIdx < root->GetNumChildren(); childIdx++) {
				LegoROI::FUN_100a8e80(root->GetChild(childIdx), p_transform, p_float, roiMap);
			}
			if (m_cameraFlag) {
				FUN_10010c30();
			}
		}
		else {
			m_roi->SetVisibility(FALSE);
			for (MxU32 i = 0; i < numROIs; i++) {
				if (roiMap[i] && roiMap[i] != m_roi) {
					roiMap[i]->SetVisibility(FALSE);
				}
			}
		}
		return SUCCESS;
	}
	else {
		return FAILURE;
	}
}

// FUNCTION: LEGO1 0x1001c450
MxResult LegoAnimActor::FUN_1001c450(LegoAnim* p_animTreePtr, float p_float, LegoROI** p_roiMap, MxU32 p_numROIs)
{
	LegoAnimActorStruct* laas = new LegoAnimActorStruct(p_float, p_animTreePtr, p_roiMap, p_numROIs);
	for (vector<LegoAnimActorStruct*>::iterator it = m_animMaps.begin(); it != m_animMaps.end(); it++) {
		if (p_float < (*it)->m_unk0x00) {
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
	char value[0x100];
	if (world) {
		if (KeyValueStringParse(value, g_strANIMATION, p_extra)) {
			char* token = strtok(value, g_parseExtraTokens);
			while (token) {
				LegoAnimPresenter* p = (LegoAnimPresenter*) world->Find("LegoAnimPresenter", token);
				if (p) {
					token = strtok(NULL, g_parseExtraTokens);
					if (token) {
						p->FUN_1006d680(this, atof(token));
					}
				}
				token = strtok(NULL, g_parseExtraTokens);
			}
		}
	}
}
