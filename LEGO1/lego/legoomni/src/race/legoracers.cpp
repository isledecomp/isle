#include "legoracers.h"

#include "anim/legoanim.h"
#include "carrace.h"
#include "define.h"
#include "jetskirace.h"
#include "legocachesoundmanager.h"
#include "legocameracontroller.h"
#include "legonavcontroller.h"
#include "legorace.h"
#include "legoracers.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "mxvariabletable.h"
#include "raceskel.h"

DECOMP_SIZE_ASSERT(EdgeReference, 0x08)
DECOMP_SIZE_ASSERT(SkeletonKickPhase, 0x10)
DECOMP_SIZE_ASSERT(LegoRaceCar, 0x200)
DECOMP_SIZE_ASSERT(LegoJetski, 0x1dc)

// name verified by BETA10 0x100cbee6
// GLOBAL: LEGO1 0x100f0a20
// GLOBAL: BETA10 0x101f5e34
EdgeReference g_skBMap[] = {
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
// GLOBAL: BETA10 0x101f5e60
const SkeletonKickPhase g_skeletonKickPhases[] = {
	{&g_skBMap[0], 0.1, 0.2, LEGORACECAR_KICK2},
	{&g_skBMap[1], 0.2, 0.3, LEGORACECAR_KICK2},
	{&g_skBMap[2], 0.3, 0.4, LEGORACECAR_KICK2},
	{&g_skBMap[2], 0.6, 0.7, LEGORACECAR_KICK1},
	{&g_skBMap[1], 0.7, 0.8, LEGORACECAR_KICK1},
	{&g_skBMap[0], 0.8, 0.9, LEGORACECAR_KICK1},
	{&g_skBMap[3], 0.1, 0.2, LEGORACECAR_KICK1},
	{&g_skBMap[4], 0.2, 0.3, LEGORACECAR_KICK1},
	{&g_skBMap[5], 0.3, 0.4, LEGORACECAR_KICK1},
	{&g_skBMap[5], 0.6, 0.7, LEGORACECAR_KICK2},
	{&g_skBMap[4], 0.7, 0.8, LEGORACECAR_KICK2},
	{&g_skBMap[3], 0.8, 0.9, LEGORACECAR_KICK2},
};

// the STRING is already declared at LEGO1 0x101020b8
// GLOBAL: LEGO1 0x100f0b10
const char* g_strSpeed = "SPEED";

// GLOBAL: LEGO1 0x100f0b14
const char* g_strJetSpeed = "jetSPEED";

// GLOBAL: LEGO1 0x100f0b18
// GLOBAL: BETA10 0x101f5f28
const char* g_srtsl18to29[] = {
	"srt018sl",
	"srt019sl",
	"srt020sl",
	"srt021sl",
	"srt022sl",
	"srt023sl",
	"srt024sl",
	"srt025sl",
	"srt026sl",
	"srt027sl",
	"srt028sl",
	"srt029sl"
};

// GLOBAL: LEGO1 0x100f0b48
// GLOBAL: BETA10 0x101f5f58
const char* g_srtsl6to10[] = {"srt006sl", "srt007sl", "srt008sl", "srt009sl", "srt010sl"};

// GLOBAL: LEGO1 0x100f0b5c
// GLOBAL: BETA10 0x101f5f6c
const char* g_emptySoundKeyList[] = {NULL};

// GLOBAL: LEGO1 0x100f0b60
// GLOBAL: BETA10 0x101f5f70
const char* g_srtrh[] = {"srt004rh", "srt005rh", "srt006rh"};

// GLOBAL: LEGO1 0x100f0b6c
// STRING: LEGO1 0x100f08c4
const char* g_srt001ra = "srt001ra";

// GLOBAL: LEGO1 0x100f0b70
// STRING: LEGO1 0x100f08bc
const char* g_soundSkel3 = "skel3";

// GLOBAL: LEGO1 0x100f0b74
// GLOBAL: BETA10 0x101f5f80
MxU32 g_srtsl18to29Index = 0;

// GLOBAL: LEGO1 0x100f0b78
// GLOBAL: BETA10 0x101f5f84
MxU32 g_srtsl6to10Index = 0;

// GLOBAL: LEGO1 0x100f0b7c
// GLOBAL: BETA10 0x101f5f88
MxU32 g_emptySoundKeyListIndex = 0;

// GLOBAL: LEGO1 0x100f0b80
// GLOBAL: BETA10 0x101f5f8c
MxU32 g_srtrhIndex = 0;

// GLOBAL: LEGO1 0x100f0b84
// GLOBAL: BETA10 0x101f5f90
MxLong g_timeLastSoundPlayed = 0;

// GLOBAL: LEGO1 0x100f0b88
// GLOBAL: BETA10 0x101f5f94
MxS32 g_unk0x100f0b88 = 0;

// GLOBAL: LEGO1 0x100f0b8c
// GLOBAL: BETA10 0x101f5f98
MxBool g_unk0x100f0b8c = TRUE;

// GLOBAL: LEGO1 0x100f0b90
const char* g_hitSnapSounds[] = {
	"Svo001Sn",
	"Svo002Sn",
	"Svo004Sn",
	"Svo005Sn",
};

// GLOBAL: LEGO1 0x100f0ba0
const char* g_hitValerieSounds[] = {
	"Svo001Va",
	"Svo003Va",
	"Svo004Va",
};

// GLOBAL: LEGO1 0x100f0bac
undefined4 g_hitSnapSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0bb0
undefined4 g_hitValerieSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0bb4
MxLong g_unk0x100f0bb4 = 0;

// Initialized at LEGO1 0x10012db0
// GLOBAL: LEGO1 0x10102af0
// GLOBAL: BETA10 0x102114c0
Mx3DPointFloat g_unk0x10102af0 = Mx3DPointFloat(0.0f, 2.0f, 0.0f);

// FUNCTION: LEGO1 0x10012950
LegoRaceCar::LegoRaceCar()
{
	m_userState = 0;
	m_skelKick1Anim = 0;
	m_skelKick2Anim = 0;
	m_unk0x5c.Clear();
	m_unk0x58 = 0;
	m_kick1B = 0;
	m_kick2B = 0;
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

// FUNCTION: LEGO1 0x10012de0
void LegoRaceCar::FUN_10012de0()
{
	g_unk0x100f0b8c = TRUE;
	g_timeLastSoundPlayed = 0;
	g_unk0x100f0b88 = 0;
}

// FUNCTION: LEGO1 0x10012e00
// FUNCTION: BETA10 0x100cb129
void LegoRaceCar::FUN_10012e00()
{
	// Note the (likely unintentional) order of operations: `%` is executed before `/`,
	// so the division is performed at runtime.
	g_srtsl18to29Index = rand() % sizeof(g_srtsl18to29) / sizeof(g_srtsl18to29[0]);
	g_srtsl6to10Index = rand() % sizeof(g_srtsl6to10) / sizeof(g_srtsl6to10[0]);
	g_emptySoundKeyListIndex = rand() % sizeof(g_emptySoundKeyList) / sizeof(g_emptySoundKeyList[0]);
	g_srtrhIndex = rand() % sizeof(g_srtrh) / sizeof(g_srtrh[0]);
}

// FUNCTION: LEGO1 0x10012e60
// FUNCTION: BETA10 0x100cb191
void LegoRaceCar::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (!m_userNavFlag) {
		if (!LegoCarRaceActor::m_unk0x0c) {
			m_maxLinearVel = p_worldSpeed;
		}
		LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	}
	else {
		LegoEntity::SetWorldSpeed(p_worldSpeed);
	}
}

// FUNCTION: LEGO1 0x10012ea0
// FUNCTION: BETA10 0x100cb220
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
// FUNCTION: BETA10 0x100cb2aa
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
		MxS32 i;

		for (i = 0; i < m_animMaps.size(); i++) {
			// It appears that the implementation in BETA10 does not use this variable
			LegoAnimActorStruct* animMap = m_animMaps[i];

			if (animMap->m_unk0x00 == -1.0f) {
				m_skelKick1Anim = animMap;
			}
			else if (animMap->m_unk0x00 == -2.0f) {
				m_skelKick2Anim = animMap;
			}
		}

		assert(m_skelKick1Anim && m_skelKick2Anim);

		// STRING: LEGO1 0x100f0bc4
		const char* edge0344 = "EDG03_44";
		m_kick1B = currentWorld->FindPathBoundary(edge0344);
		assert(m_kick1B);

		// STRING: LEGO1 0x100f0bb8
		const char* edge0354 = "EDG03_54";
		m_kick2B = currentWorld->FindPathBoundary(edge0354);
		assert(m_kick2B);

		for (i = 0; i < sizeOfArray(g_skBMap); i++) {
			assert(g_skBMap[i].m_name);
			g_skBMap[i].m_b = currentWorld->FindPathBoundary(g_skBMap[i].m_name);
			assert(g_skBMap[i].m_b);
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
		a = m_skelKick1Anim;
	}
	else {
		assert(m_userState == LEGORACECAR_KICK2);
		a = m_skelKick2Anim;
	}

	assert(a && a->GetAnimTreePtr() && a->GetAnimTreePtr()->GetCamAnim());

	if (a->GetAnimTreePtr()) {
		deltaTime = p_param - m_unk0x58;

		if (a->GetDuration() <= deltaTime || deltaTime < 0.0) {
			if (m_userState == LEGORACECAR_KICK1) {
				LegoUnknown100db7f4** edges = m_kick1B->GetEdges();
				m_destEdge = edges[2];
				m_boundary = m_kick1B;
			}
			else {
				LegoUnknown100db7f4** edges = m_kick1B->GetEdges();
				m_destEdge = edges[1];
				m_boundary = m_kick2B;
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

	CarRace* r = (CarRace*) CurrentWorld(); // called `r` in BETA10
	assert(r);

	RaceSkel* s = r->GetSkeleton(); // called `s` in BETA10
	assert(s);

	float skeletonCurAnimPosition;
	float skeletonCurAnimDuration;

	s->GetCurrentAnimData(&skeletonCurAnimPosition, &skeletonCurAnimDuration);

	float skeletonCurAnimPhase = skeletonCurAnimPosition / skeletonCurAnimDuration;

	for (MxS32 i = 0; i < sizeOfArray(g_skeletonKickPhases); i++) {
		if (m_boundary == current->m_edgeRef->m_b && current->m_lower <= skeletonCurAnimPhase &&
			skeletonCurAnimPhase <= current->m_upper) {
			m_userState = current->m_userState;
		}
		current = &current[1];
	}

	if (m_userState != LEGORACECAR_KICK1 && m_userState != LEGORACECAR_KICK2) {
		MxTrace(
			// STRING: BETA10 0x101f64c8
			"Got kicked in boundary %s %d %g:%g %g\n",
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
void LegoRaceCar::Animate(float p_time)
{
	if (m_userNavFlag && (m_userState == LEGORACECAR_KICK1 || m_userState == LEGORACECAR_KICK2)) {
		FUN_10012ff0(p_time);
		return;
	}

	LegoCarRaceActor::Animate(p_time);

	if (m_userNavFlag && m_userState == LEGORACECAR_UNKNOWN_1) {
		if (HandleSkeletonKicks(p_time)) {
			return;
		}
	}

	if (LegoCarRaceActor::m_unk0x0c == 1) {
		FUN_1005d4b0();

		if (!m_userNavFlag) {
			FUN_10080590(p_time);
			return;
		}

		float absoluteSpeed = abs(m_worldSpeed);
		float maximumSpeed = NavController()->GetMaxLinearVel();
		char buffer[200];

		sprintf(buffer, "%g", absoluteSpeed / maximumSpeed);

		VariableTable()->SetVariable(g_strSpeed, buffer);

		if (m_sound) {
			// pitches up the engine sound based on the velocity
			if (absoluteSpeed > 0.83 * maximumSpeed) {
				m_frequencyFactor = 1.9f;
			}
			else {
				// this value seems to simulate RPM based on the gear
				MxS32 gearRpmFactor = (MxS32) (6.0 * absoluteSpeed) % 100;
				m_frequencyFactor = gearRpmFactor / 80.0 + 0.7;
			}
		}

		if (absoluteSpeed != 0.0f) {
			g_unk0x100f0b88 = p_time;
			g_unk0x100f0b8c = FALSE;
		}

		if (p_time - g_unk0x100f0b88 > 5000.0f && !g_unk0x100f0b8c) {
			SoundManager()->GetCacheSoundManager()->Play(g_srt001ra, NULL, 0);
			g_unk0x100f0b8c = TRUE;
		}
	}
}

// FUNCTION: LEGO1 0x100133c0
// FUNCTION: BETA10 0x100cbb84
MxResult LegoRaceCar::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	// Note: Code duplication with LegoRaceActor::HitActor
	if (!p_actor->GetUserNavFlag()) {
		if (p_actor->GetActorState() != c_initial) {
			return FAILURE;
		}

		if (p_bool) {
			LegoROI* roi = p_actor->GetROI(); // name verified by BETA10 0x100cbbf5
			assert(roi);
			MxMatrix matr;
			matr = roi->GetLocal2World();

			Vector3(matr[3]) += g_unk0x10102af0;
			roi->FUN_100a58f0(matr);

			p_actor->SetActorState(c_two);
		}

		if (m_userNavFlag) {
			MxBool actorIsStuds = strcmpi(p_actor->GetROI()->GetName(), "studs") == 0;
			MxBool actorIsRhoda = strcmpi(p_actor->GetROI()->GetName(), "rhoda") == 0;
			MxLong time = Timer()->GetTime();

			const char* soundKey = NULL;
			MxLong timeElapsed = time - g_timeLastSoundPlayed;

			if (timeElapsed > 3000) {
				if (p_bool) {
					if (actorIsStuds) {
						soundKey = g_srtsl18to29[g_srtsl18to29Index++];
						if (g_srtsl18to29Index >= sizeOfArray(g_srtsl18to29)) {
							g_srtsl18to29Index = 0;
						}
					}
					else if (actorIsRhoda) {
						soundKey = g_emptySoundKeyList[g_emptySoundKeyListIndex++];
						if (g_emptySoundKeyListIndex >= sizeOfArray(g_emptySoundKeyList)) {
							g_emptySoundKeyListIndex = 0;
						}
					}
				}
				else {
					if (actorIsStuds) {
						soundKey = g_srtsl6to10[g_srtsl6to10Index++];
						if (g_srtsl6to10Index >= sizeOfArray(g_srtsl6to10)) {
							g_srtsl6to10Index = 0;
						}
					}
					else if (actorIsRhoda) {
						soundKey = g_srtrh[g_srtrhIndex++];
						if (g_srtrhIndex >= sizeOfArray(g_srtrh)) {
							g_srtrhIndex = 0;
						}
					}
				}

				if (soundKey) {
					SoundManager()->GetCacheSoundManager()->Play(soundKey, NULL, FALSE);
					g_timeLastSoundPlayed = g_unk0x100f3308 = time;
				}
			}

			if (p_bool && m_worldSpeed != 0) {
				return SUCCESS;
			}

			return FAILURE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10013600
// FUNCTION: BETA10 0x100cbe60
MxResult LegoRaceCar::VTable0x9c()
{
	MxResult result;

	if (m_userNavFlag) {
		result = LegoCarRaceActor::VTable0x9c();

		if (m_boundary) {
			MxS32 bVar2 = 0;

			for (MxS32 i = 0; i < sizeOfArray(g_skBMap); i++) {
				assert(g_skBMap[i].m_b);
				if (m_boundary == g_skBMap[i].m_b) {
					bVar2 = 1;
					break;
				}
			}

			if (m_userState == LEGORACECAR_UNKNOWN_1) {
				if (!bVar2) {
					m_userState = LEGORACECAR_UNKNOWN_0;
				}
			}
			else {
				m_userState = LEGORACECAR_UNKNOWN_1;
			}
		}
	}
	else {
		result = LegoCarRaceActor::VTable0x9c();
	}

	return result;
}

// FUNCTION: LEGO1 0x10013670
void LegoRaceCar::FUN_10013670()
{
	g_hitSnapSoundsIndex = (rand() & 0xc) >> 2;

	// Inlining the `rand()` causes this function to mismatch
	MxU32 uVar1 = rand();
	g_hitValerieSoundsIndex = uVar1 % 0xc >> 2;
}

// FUNCTION: LEGO1 0x100136a0
// FUNCTION: BETA10 0x100cbf7e
void LegoJetski::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (!m_userNavFlag) {
		if (!LegoCarRaceActor::m_unk0x0c) {
			m_maxLinearVel = p_worldSpeed;
		}
		LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	}
	else {
		LegoEntity::SetWorldSpeed(p_worldSpeed);
	}
}

// FUNCTION: LEGO1 0x100136f0
// FUNCTION: BETA10 0x100cc01a
void LegoJetski::FUN_100136f0(float p_worldSpeed)
{
	if (p_worldSpeed < 0) {
		LegoCarRaceActor::m_unk0x0c = 2;
		m_maxLinearVel = 0;
		SetWorldSpeed(0);
	}
	else {
		m_maxLinearVel = p_worldSpeed;
	}
}

// FUNCTION: LEGO1 0x10013740
// FUNCTION: BETA10 0x100cc0ae
void LegoJetski::Animate(float p_time)
{
	LegoJetskiRaceActor::Animate(p_time);

	if (LegoCarRaceActor::m_unk0x0c == 1) {
		FUN_1005d4b0();

		if (!m_userNavFlag) {
			FUN_10080590(p_time);
			return;
		}

		float absoluteSpeed = abs(m_worldSpeed);
		float speedRatio = absoluteSpeed / NavController()->GetMaxLinearVel();
		char buffer[200];

		sprintf(buffer, "%g", speedRatio);

		VariableTable()->SetVariable(g_strJetSpeed, buffer);

		if (m_sound) {
			m_frequencyFactor = speedRatio * 1.2 + 0.7;
		}
	}
}

// FUNCTION: LEGO1 0x10013820
// FUNCTION: BETA10 0x100cc335
LegoJetski::LegoJetski()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10013aa0
// FUNCTION: BETA10 0x100cc58e
LegoJetski::~LegoJetski()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10013bb0
// FUNCTION: BETA10 0x100cc6df
void LegoJetski::ParseAction(char* p_extra)
{
	char buffer[256];

	LegoAnimActor::ParseAction(p_extra);
	LegoRaceMap::ParseAction(p_extra);
	JetskiRace* currentWorld = (JetskiRace*) CurrentWorld();

	if (KeyValueStringParse(buffer, g_strCOMP, p_extra) && currentWorld) {
		currentWorld->VTable0x7c(this, atoi(buffer));
	}
}

// FUNCTION: LEGO1 0x10013c30
// FUNCTION: BETA10 0x100cc76a
MxLong LegoJetski::Notify(MxParam& p_param)
{
	return LegoRaceMap::Notify(p_param);
}

// FUNCTION: LEGO1 0x10013c40
MxResult LegoJetski::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	// Note: very similar to LegoRaceCar::HitActor

	if (!p_actor->GetUserNavFlag()) {
		if (p_actor->GetActorState() != c_initial) {
			return FAILURE;
		}

		if (p_bool) {
			LegoROI* roi = p_actor->GetROI();
			MxMatrix matr;
			matr = roi->GetLocal2World();

			Vector3(matr[3]) += g_unk0x10102af0;
			roi->FUN_100a58f0(matr);

			p_actor->SetActorState(c_two);
		}

		if (m_userNavFlag) {
			MxBool actorIsSnap = strcmpi(p_actor->GetROI()->GetName(), "snap") == 0;
			MxBool actorIsValerie = strcmpi(p_actor->GetROI()->GetName(), "valerie") == 0;
			MxLong time = Timer()->GetTime();

			const char* soundKey = NULL;
			MxLong timeElapsed = time - g_unk0x100f0bb4;

			if (timeElapsed > 3000) {
				if (actorIsSnap) {
					soundKey = g_hitSnapSounds[g_hitSnapSoundsIndex++];
					if (g_hitSnapSoundsIndex >= sizeOfArray(g_hitSnapSounds)) {
						g_hitSnapSoundsIndex = 0;
					}
				}
				else if (actorIsValerie) {
					soundKey = g_hitValerieSounds[g_hitValerieSoundsIndex++];
					if (g_hitValerieSoundsIndex >= sizeOfArray(g_hitValerieSounds)) {
						g_hitValerieSoundsIndex = 0;
					}
				}

				if (soundKey) {
					SoundManager()->GetCacheSoundManager()->Play(soundKey, NULL, FALSE);
					g_timeLastSoundPlayed = g_unk0x100f3308 = time;
				}
			}

			if (p_bool && m_worldSpeed != 0) {
				return SUCCESS;
			}

			return FAILURE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10014150
MxU32 LegoJetski::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	return LegoJetskiRaceActor::VTable0x6c(p_boundary, p_v1, p_v2, p_f1, p_f2, p_v3);
}

// FUNCTION: LEGO1 0x100141d0
void LegoJetski::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	LegoJetskiRaceActor::SwitchBoundary(p_boundary, p_edge, p_unk0xe4);
}

// FUNCTION: LEGO1 0x10014210
MxResult LegoJetski::VTable0x9c()
{
	return LegoJetskiRaceActor::VTable0x9c();
}

// FUNCTION: LEGO1 0x10014500
// FUNCTION: BETA10 0x100cd5e0
MxU32 LegoRaceCar::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	return LegoCarRaceActor::VTable0x6c(p_boundary, p_v1, p_v2, p_f1, p_f2, p_v3);
}

// FUNCTION: LEGO1 0x10014560
// FUNCTION: BETA10 0x100cd660
void LegoRaceCar::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	LegoCarRaceActor::SwitchBoundary(p_boundary, p_edge, p_unk0xe4);
}
