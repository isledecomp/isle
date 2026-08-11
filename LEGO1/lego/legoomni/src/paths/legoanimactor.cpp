// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class LaL000;
class LaL001;
class LaL002;
class LaL003;
class LaL004;
class LaL005;
class LaL006;
class LaL007;
class LaL008;
class LaL009;
class LaL010;
class LaL011;
class LaL012;
class LaL013;
class LaL014;
class LaL015;
class LaL016;
class LaL017;
class LaL018;
class LaL019;
class LaL020;
class LaL021;
class LaL022;
class LaL023;
class LaL024;
class LaL025;
class LaL026;
class LaL027;
class LaL028;
class LaL029;
class LaL030;
class LaL031;
class LaL032;
class LaL033;
class LaL034;
class LaL035;
class LaL036;
class LaL037;
class LaL038;
class LaL039;
class LaL040;
class LaL041;
class LaL042;
class LaL043;
class LaL044;
class LaL045;
class LaL046;
class LaL047;
class LaL048;
class LaL049;
class LaL050;
class LaL051;
class LaL052;
class LaL053;
class LaL054;
class LaL055;
class LaL056;
class LaL057;
class LaL058;
class LaL059;
class LaL060;
class LaL061;
class LaL062;
class LaL063;
class LaL064;
class LaL065;
class LaL066;
class LaL067;
class LaL068;
class LaL069;
class LaL070;
class LaL071;
class LaL072;
class LaL073;
class LaL074;
class LaL075;
class LaL076;
class LaL077;
class LaL078;
class LaL079;
class LaL080;
class LaL081;
class LaL082;
class LaL083;
class LaL084;
class LaL085;
class LaL086;
class LaL087;
class LaL088;
class LaL089;
class LaL090;
class LaL091;
class LaL092;
class LaL093;
class LaL094;
class LaL095;
class LaL096;
class LaL097;
class LaL098;
class LaL099;
class LaL100;
class LaL101;
class LaL102;
class LaL103;
class LaL104;
class LaL105;
class LaL106;
class LaL107;
class LaL108;
class LaL109;
class LaL110;
class LaL111;
class LaL112;
class LaL113;
class LaL114;
class LaL115;
class LaL116;
class LaL117;
class LaL118;
class LaL119;
class LaL120;
class LaL121;
class LaL122;
class LaL123;
class LaL124;
class LaL125;
class LaL126;
class LaL127;
class LaL128;
class LaL129;
class LaL130;
class LaL131;
class LaL132;
class LaL133;
class LaL134;
class LaL135;
class LaL136;
#include "legoanimactor.h"

#include "anim/legoanim.h"
#include "define.h"
#include "legoanimpresenter.h"
#include "legopathboundary.h"
#include "legoworld.h"
#include "misc.h"
#include "mxutilities.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(LegoAnimActor, 0x174)
DECOMP_SIZE_ASSERT(LegoAnimActorStruct, 0x20)

// FUNCTION: LEGO1 0x1001bf80
// FUNCTION: BETA10 0x1003dc10
LegoAnimActorStruct::LegoAnimActorStruct(
	float p_worldSpeed,
	LegoAnim* p_AnimTreePtr,
	LegoROI** p_roiMap,
	MxU32 p_numROIs
)
{
	m_worldSpeed = p_worldSpeed;
	m_AnimTreePtr = p_AnimTreePtr;
	m_roiMap = p_roiMap;
	m_numROIs = p_numROIs;
}

// FUNCTION: LEGO1 0x1001c0a0
// FUNCTION: BETA10 0x1003dca1
LegoAnimActorStruct::~LegoAnimActorStruct()
{
	for (MxU16 i = 0; i < m_unk0x10.size(); i++) {
		delete m_unk0x10[i];
	}
}

// FUNCTION: LEGO1 0x1001c130
// FUNCTION: BETA10 0x1003df3a
float LegoAnimActorStruct::GetDuration()
{
	assert(m_AnimTreePtr);
	return m_AnimTreePtr->GetDuration();
}

// FUNCTION: LEGO1 0x1001c140
// FUNCTION: BETA10 0x1003dfe4
LegoAnimActor::~LegoAnimActor()
{
	for (MxS32 i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]) {
			delete m_animMaps[i];
		}
	}
}

// FUNCTION: LEGO1 0x1001c1f0
// FUNCTION: BETA10 0x1003f240
MxResult LegoAnimActor::GetTimeInCycle(float& p_timeInCycle)
{
	float duration = (float) m_animMaps[m_curAnim]->m_AnimTreePtr->GetDuration();
	p_timeInCycle = m_actorTime - duration * ((MxS32) (m_actorTime / duration));
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001c240
// FUNCTION: BETA10 0x1003e0db
void LegoAnimActor::ApplyTransform(Matrix4& p_transform)
{
	float timeInCycle;
	LegoPathActor::ApplyTransform(p_transform);

	if (m_curAnim >= 0) {
		GetTimeInCycle(timeInCycle);
		AnimateWithTransform(timeInCycle, p_transform);
	}
}

// FUNCTION: LEGO1 0x1001c290
// FUNCTION: BETA10 0x1003e144
void LegoAnimActor::Animate(float p_time)
{
	assert(m_roi);

	if (m_transformTime == 0) {
		m_transformTime = p_time - 1.0f;
	}

	if (m_actorState == c_initial && !m_userNavFlag && m_worldSpeed <= 0) {
		if (m_curAnim >= 0) {
			MxMatrix transform(m_local2World);
			float timeInCycle;
			GetTimeInCycle(timeInCycle);
			AnimateWithTransform(timeInCycle, transform);
		}

		m_transformTime = m_actorTime = p_time;
	}
	else {
		LegoPathActor::Animate(p_time);
	}
}

// FUNCTION: LEGO1 0x1001c360
// FUNCTION: BETA10 0x1003e2d3
MxResult LegoAnimActor::AnimateWithTransform(float p_time, Matrix4& p_transform)
{
	if (p_time >= 0) {
		assert((m_curAnim >= 0) && (m_curAnim < m_animMaps.size()));

		LegoROI** roiMap = m_animMaps[m_curAnim]->m_roiMap;
		MxU32 numROIs = m_animMaps[m_curAnim]->m_numROIs;

		if (m_boundary->GetVisibility()) {
			// name verified by BETA10 0x1003e407
			LegoTreeNode* n = m_animMaps[m_curAnim]->m_AnimTreePtr->GetRoot();

			assert(roiMap && n && m_roi && m_boundary);

			m_roi->SetVisibility(TRUE);

			for (MxS32 i = 0; i < numROIs; i++) {
				LegoROI* roi = roiMap[i];

				if (roi != NULL && m_roi != roi) {
					roi->SetVisibility(TRUE);
				}
			}

			for (i = 0; i < n->GetNumChildren(); i++) {
				LegoROI::ApplyAnimationTransformation(n->GetChild(i), p_transform, p_time, roiMap);
			}

			if (m_cameraFlag) {
				TransformPointOfView();
			}
		}
		else {
			MxU32 i;
			m_roi->SetVisibility(FALSE);

			for (i = 0; i < numROIs; i++) {
				LegoROI* roi = roiMap[i];

				if (roi != NULL && m_roi != roi) {
					roi->SetVisibility(FALSE);
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
// FUNCTION: BETA10 0x1003e590
MxResult LegoAnimActor::CreateAnimActorStruct(
	LegoAnim* p_AnimTreePtr,
	float p_worldSpeed,
	LegoROI** p_roiMap,
	MxU32 p_numROIs
)
{
	// the capitalization of `p_AnimTreePtr` was taken from BETA10
	assert(p_AnimTreePtr && p_roiMap);

	LegoAnimActorStruct* laas = new LegoAnimActorStruct(p_worldSpeed, p_AnimTreePtr, p_roiMap, p_numROIs);

	for (vector<LegoAnimActorStruct*>::iterator it = m_animMaps.begin(); it != m_animMaps.end(); it++) {
		if (p_worldSpeed < (*it)->m_worldSpeed) {
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
// FUNCTION: BETA10 0x1003e747
void LegoAnimActor::ClearMaps()
{
	for (MxU32 i = 0; i < m_animMaps.size(); i++) {
		delete m_animMaps[i];
	}

	m_animMaps.clear();
	m_curAnim = -1;
}

// FUNCTION: LEGO1 0x1001c870
// FUNCTION: BETA10 0x1003e7e4
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

		if (m_worldSpeed >= m_animMaps[m_animMaps.size() - 1]->m_worldSpeed) {
			m_curAnim = m_animMaps.size() - 1;
		}
		else {
			for (MxU32 i = 0; i < m_animMaps.size(); i++) {
				if (m_worldSpeed <= m_animMaps[i]->m_worldSpeed) {
					m_curAnim = i;
					break;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x1001c920
// FUNCTION: BETA10 0x1003e914
void LegoAnimActor::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	LegoWorld* world = CurrentWorld();
	char value[256];

	if (world) {
		if (KeyValueStringParse(value, g_strANIMATION, p_extra)) {
			// name verified by BETA10 0x1003ea46
			char* token = strtok(value, g_parseExtraTokens);

			while (token) {
				// name verified by BETA10 0x1003e9f5
				LegoLocomotionAnimPresenter* p = (LegoLocomotionAnimPresenter*) world->Find("LegoAnimPresenter", token);

				assert(p);

				if (p != NULL) {
					token = strtok(NULL, g_parseExtraTokens);
					assert(token);

					if (token) {
						p->CreateROIAndBuildMap(this, atof(token));
					}
				}

				token = strtok(NULL, g_parseExtraTokens);
			}
		}
	}
}

// Record carriers (scaffolding): 8 units at end of unit for LegoAnimActor::CreateAnimActorStruct.
// ClearMaps wants 7 and the vector dtor 18/19: the three are anti-phase.
class MxUnkRecordLAA00;
class MxUnkRecordLAA01;
class MxUnkRecordLAA02;
class MxUnkRecordLAA03;
class MxUnkRecordLAA04;
class MxUnkRecordLAA05;
class MxUnkRecordLAA06;
class MxUnkRecordLAA07;
