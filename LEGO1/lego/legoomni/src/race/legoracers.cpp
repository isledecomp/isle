#include "legoracers.h"

#include "anim/legoanim.h"
#include "carrace.h"
#include "define.h"
#include "legocachesoundmanager.h"
#include "legocameracontroller.h"
#include "legonavcontroller.h"
#include "legorace.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxutilities.h"
#include "mxvariabletable.h"
#include "raceskel.h"

DECOMP_SIZE_ASSERT(EdgeReference, 0x08)
DECOMP_SIZE_ASSERT(SkeletonKickPhase, 0x10)
DECOMP_SIZE_ASSERT(LegoRaceCar, 0x200)

// GLOBAL: LEGO1 0x100f0a20
EdgeReference LegoRaceCar::g_edgeReferences[] = {
	{// STRING: LEGO1 0x100f0a10
	 "EDG03_772",
	 NULL
	},
	{// STRING: LEGO1 0x100f0a04
	 "EDG03_773",
	 NULL
	},
	{// STRING: LEGO1 0x100f09f8
	 "EDG03_774",
	 NULL
	},
	{// STRING: LEGO1 0x100f09ec
	 "EDG03_775",
	 NULL
	},
	{// STRING: LEGO1 0x100f09e0
	 "EDG03_776",
	 NULL
	},
	{// STRING: LEGO1 0x100f09d4
	 "EDG03_777",
	 NULL
	}
};

// GLOBAL: LEGO1 0x100f0a50
const SkeletonKickPhase LegoRaceCar::g_skeletonKickPhases[] = {
	{&LegoRaceCar::g_edgeReferences[0], 0.1, 0.2, LEGORACECAR_KICK2},
	{&LegoRaceCar::g_edgeReferences[1], 0.2, 0.3, LEGORACECAR_KICK2},
	{&LegoRaceCar::g_edgeReferences[2], 0.3, 0.4, LEGORACECAR_KICK2},
	{&LegoRaceCar::g_edgeReferences[2], 0.6, 0.7, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[1], 0.7, 0.8, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[0], 0.8, 0.9, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[3], 0.1, 0.2, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[4], 0.2, 0.3, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[5], 0.3, 0.4, LEGORACECAR_KICK1},
	{&LegoRaceCar::g_edgeReferences[5], 0.6, 0.7, LEGORACECAR_KICK2},
	{&LegoRaceCar::g_edgeReferences[4], 0.7, 0.8, LEGORACECAR_KICK2},
	{&LegoRaceCar::g_edgeReferences[3], 0.8, 0.9, LEGORACECAR_KICK2},
};

// GLOBAL: LEGO1 0x100f0b10
const char* LegoRaceCar::g_strSpeedCopy = g_strSPEED;

// GLOBAL: LEGO1 0x100f0b6c
// STRING: LEGO1 0x100f08c4
const char* LegoRaceCar::g_srt001ra = "srt001ra";

// GLOBAL: LEGO1 0x100f0b70
// STRING: LEGO1 0x100f08bc
const char* LegoRaceCar::g_soundSkel3 = "skel3";

// GLOBAL: LEGO1 0x100f0b88
// GLOBAL: BETA10 0x101f5f94
int LegoRaceCar::g_unk0x100f0b88 = 0;

// GLOBAL: LEGO1 0x100f0b8c
// GLOBAL: BETA10 0x101f5f98
MxBool LegoRaceCar::g_unk0x100f0b8c = FALSE;

// FUNCTION: LEGO1 0x10012950
LegoRaceCar::LegoRaceCar()
{
	m_userState = 0;
	m_unk0x70 = 0;
	m_unk0x74 = 0;
	m_unk0x5c.Clear();
	m_unk0x58 = 0;
	m_unk0x78 = 0;
	m_unk0x7c = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10012c80
LegoRaceCar::~LegoRaceCar()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10012d90
MxLong LegoRaceCar::Notify(MxParam& p_param)
{
	return LegoRaceMap::Notify(p_param);
}

// FUNCTION: LEGO1 0x10012e60
void LegoRaceCar::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (!m_userNavFlag) {
		if (!LegoCarRaceActor::m_unk0x0c) {
			m_maxLinearVel = p_worldSpeed;
		}
		LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	}
	else {
		m_worldSpeed = p_worldSpeed;
	}
}

// FUNCTION: LEGO1 0x10012ea0
void LegoRaceCar::SetMaxLinearVelocity(float p_maxLinearVelocity)
{
	if (p_maxLinearVelocity < 0) {
		LegoCarRaceActor::m_unk0x0c = 2;
		m_maxLinearVel = 0;
		SetWorldSpeed(0);
	}
	else {
		m_maxLinearVel = p_maxLinearVelocity;
	}
}

// FUNCTION: LEGO1 0x10012ef0
void LegoRaceCar::ParseAction(char* p_extra)
{
	char buffer[256];

	LegoAnimActor::ParseAction(p_extra);
	LegoRaceMap::ParseAction(p_extra);
	LegoRace* currentWorld = (LegoRace*) CurrentWorld();

	if (KeyValueStringParse(buffer, g_strCOMP, p_extra) && currentWorld) {
		currentWorld->VTable0x7c(this, atoi(buffer));
	}

	if (m_userNavFlag) {
		for (MxU32 i = 0; i < m_animMaps.size(); i++) {
			LegoAnimActorStruct* animMap = m_animMaps[i];

			if (animMap->m_unk0x00 == -1.0f) {
				m_unk0x70 = animMap;
			}
			else if (animMap->m_unk0x00 == -2.0f) {
				m_unk0x74 = animMap;
			}
		}

		// STRING: LEGO1 0x100f0bc4
		const char* edge0344 = "EDG03_44";
		m_unk0x78 = currentWorld->FindPathBoundary(edge0344);
		// STRING: LEGO1 0x100f0bb8
		const char* edge0354 = "EDG03_54";
		m_unk0x7c = currentWorld->FindPathBoundary(edge0354);

		for (MxS32 j = 0; j < sizeOfArray(g_edgeReferences); j++) {
			g_edgeReferences[j].m_data = currentWorld->FindPathBoundary(g_edgeReferences[j].m_name);
		}
	}
}

// FUNCTION: LEGO1 0x10012ff0
// FUNCTION: BETA10 0x100cb60e
void LegoRaceCar::FUN_10012ff0(float p_param)
{
	LegoAnimActorStruct* a; // called `a` in BETA10
	float deltaTime;

	if (m_userState == LEGORACECAR_KICK1) {
		a = m_unk0x70;
	}
	else {
		assert(m_userState == LEGORACECAR_KICK2);
		a = m_unk0x74;
	}

	assert(a && a->GetAnimTreePtr() && a->GetAnimTreePtr()->GetCamAnim());

	if (a->GetAnimTreePtr()) {
		deltaTime = p_param - m_unk0x58;

		if (a->GetDuration() <= deltaTime || deltaTime < 0.0) {
			if (m_userState == LEGORACECAR_KICK1) {
				LegoEdge** edges = m_unk0x78->GetEdges();
				m_destEdge = (LegoUnknown100db7f4*) (edges[2]);
				m_boundary = m_unk0x78;
			}
			else {
				LegoEdge** edges = m_unk0x78->GetEdges();
				m_destEdge = (LegoUnknown100db7f4*) (edges[1]);
				m_boundary = m_unk0x7c;
			}

			m_userState = LEGORACECAR_UNKNOWN_0;
		}
		else if (a->GetAnimTreePtr()->GetCamAnim()) {
			MxMatrix transformationMatrix;

			LegoWorld* r = CurrentWorld(); // called `r` in BETA10
			assert(r);

			transformationMatrix.SetIdentity();

			// Possible bug in the original code: The first argument is not initialized
			a->GetAnimTreePtr()->GetCamAnim()->FUN_1009f490(deltaTime, transformationMatrix);

			if (r->GetCamera()) {
				r->GetCamera()->FUN_100123e0(transformationMatrix, 0);
			}

			m_roi->FUN_100a58f0(transformationMatrix);
		}
	}
}

// FUNCTION: LEGO1 0x10013130
// FUNCTION: BETA10 0x100cce50
MxU32 LegoRaceCar::HandleSkeletonKicks(float p_param1)
{
	const SkeletonKickPhase* current = g_skeletonKickPhases;

	// TODO: Type is guesswork so far
	CarRace* r = (CarRace*) CurrentWorld(); // called `r` in BETA10
	assert(r);

	RaceSkel* s = (RaceSkel*) r->GetUnk0x150(); // called `s` in BETA10
	assert(s);

	float skeletonCurAnimPosition;
	float skeletonCurAnimDuration;

	s->GetCurrentAnimData(&skeletonCurAnimPosition, &skeletonCurAnimDuration);

	float skeletonCurAnimPhase = skeletonCurAnimPosition / skeletonCurAnimDuration;

	for (MxS32 i = 0; i < sizeOfArray(g_skeletonKickPhases); i++) {
		if (m_boundary == current->m_edgeRef->m_data && current->m_lower <= skeletonCurAnimPhase &&
			skeletonCurAnimPhase <= current->m_upper) {
			m_userState = current->m_userState;
		}
		current = &current[1];
	}

	if (m_userState != LEGORACECAR_KICK1 && m_userState != LEGORACECAR_KICK2) {
		MxTrace(
			// STRING: BETA10 0x101f64c8
			"Got kicked in boundary %s %d %g:%g %g\n",
			// TODO: same as in above comparison
			m_boundary->GetName(),
			skeletonCurAnimPosition,
			skeletonCurAnimDuration,
			skeletonCurAnimPhase
		);
		return FALSE;
	}

	m_unk0x58 = p_param1;
	SoundManager()->GetCacheSoundManager()->Play(g_soundSkel3, NULL, FALSE);

	return TRUE;
}

// FUNCTION: LEGO1 0x100131f0
// FUNCTION: BETA10 0x100cb88a
void LegoRaceCar::VTable0x70(float p_float)
{
	if (m_userNavFlag != 0 && (m_userState == LEGORACECAR_KICK1 || m_userState == LEGORACECAR_KICK2)) {
		FUN_10012ff0(p_float);
		return;
	}

	LegoCarRaceActor::VTable0x70(p_float);

	if (m_userNavFlag != 0 && m_userState == LEGORACECAR_UNKNOWN_1) {
		if (HandleSkeletonKicks(p_float)) {
			return;
		}
	}

	if (LegoCarRaceActor::m_unk0x0c == 1) {
		FUN_1005d4b0();

		if (m_userNavFlag == 0) {
			FUN_10080590(p_float);
			return;
		}

		float absoluteSpeed = abs(m_worldSpeed);
		float maximumSpeed = NavController()->GetMaxLinearVel();
		char buffer[200];

		sprintf(buffer, "%g", absoluteSpeed / maximumSpeed);

		VariableTable()->SetVariable(g_strSpeedCopy, buffer);

		if (m_sound) {
			// pitches up the engine sound based on the velocity
			if (0.83 * maximumSpeed < absoluteSpeed) {
				m_frequencyFactor = 1.9f;
			}
			else {
				// this value seems to simulate RPM based on the gear
				int gear_rpm_factor = (int) (6.0 * absoluteSpeed) % 100;
				m_frequencyFactor = gear_rpm_factor / 80.0 + 0.7;
			}
		}

		if (absoluteSpeed != 0.0f) {
			g_unk0x100f0b88 = p_float;
			g_unk0x100f0b8c = FALSE;
		}

		if (5000.0f < p_float - g_unk0x100f0b88 && !g_unk0x100f0b8c) {
			SoundManager()->GetCacheSoundManager()->Play(g_srt001ra, NULL, 0);
			g_unk0x100f0b8c = TRUE;
		}
	}
}

// STUB: LEGO1 0x100133c0
MxResult LegoRaceCar::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10013600
MxResult LegoRaceCar::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10014500
MxU32 LegoRaceCar::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014560
void LegoRaceCar::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	// TODO
}
