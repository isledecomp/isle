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
// GLOBAL: BETA10 0x101f5e30
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
SkeletonKickPhase g_skeletonKickPhases[] = {
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
const char* g_playerHitStudsSounds[] = {
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
const char* g_studsHitPlayerSounds[] = {"srt006sl", "srt007sl", "srt008sl", "srt009sl", "srt010sl"};

// GLOBAL: LEGO1 0x100f0b5c
// GLOBAL: BETA10 0x101f5f6c
const char* g_playerHitRhodaSounds[] = {NULL};

// GLOBAL: LEGO1 0x100f0b60
// GLOBAL: BETA10 0x101f5f70
const char* g_rhodaHitPlayerSounds[] = {"srt004rh", "srt005rh", "srt006rh"};

// GLOBAL: LEGO1 0x100f0b6c
// STRING: LEGO1 0x100f08c4
const char* g_youCantStopSound = "srt001ra";

// GLOBAL: LEGO1 0x100f0b70
// STRING: LEGO1 0x100f08bc
const char* g_soundSkel3 = "skel3";

// GLOBAL: LEGO1 0x100f0b74
// GLOBAL: BETA10 0x101f5f80
MxU32 g_playerHitStudsSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0b78
// GLOBAL: BETA10 0x101f5f84
MxU32 g_studsHitPlayerSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0b7c
// GLOBAL: BETA10 0x101f5f88
MxU32 g_playerHitRhodaSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0b80
// GLOBAL: BETA10 0x101f5f8c
MxU32 g_rhodaHitPlayerSoundsIndex = 0;

// GLOBAL: LEGO1 0x100f0b84
// GLOBAL: BETA10 0x101f5f90
MxLong g_timeLastRaceCarSoundPlayed = 0;

// GLOBAL: LEGO1 0x100f0b88
// GLOBAL: BETA10 0x101f5f94
MxS32 g_timePlayerLastMoved = 0;

// GLOBAL: LEGO1 0x100f0b8c
// GLOBAL: BETA10 0x101f5f98
MxBool g_playedYouCantStopSound = TRUE;

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
MxLong g_timeLastJetskiSoundPlayed = 0;

// FUNCTION: LEGO1 0x10012950
// FUNCTION: BETA10 0x100cad10
LegoRaceCar::LegoRaceCar()
{
	m_userState = 0;
	m_skelKick1Anim = 0;
	m_skelKick2Anim = 0;
	m_unk0x5c.Clear();
	m_kickStart = 0;
	m_kick1B = 0;
	m_kick2B = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10012c80
// FUNCTION: BETA10 0x100caf67
LegoRaceCar::~LegoRaceCar()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10012d90
// FUNCTION: BETA10 0x100cb0bd
MxLong LegoRaceCar::Notify(MxParam& p_param)
{
	return LegoRaceMap::Notify(p_param);
}

// Initialized at LEGO1 0x10012db0
// GLOBAL: LEGO1 0x10102af0
// GLOBAL: BETA10 0x102114c0
Mx3DPointFloat g_hitOffset = Mx3DPointFloat(0.0f, 2.0f, 0.0f);

// FUNCTION: LEGO1 0x10012de0
void LegoRaceCar::InitYouCantStopSound()
{
	// Init to TRUE so we don't play "you can't stop in the middle of the race!" before the player ever moves
	g_playedYouCantStopSound = TRUE;
	g_timeLastRaceCarSoundPlayed = 0;
	g_timePlayerLastMoved = 0;
}

// FUNCTION: LEGO1 0x10012e00
// FUNCTION: BETA10 0x100cb129
void LegoRaceCar::InitSoundIndices()
{
	// Note the (likely unintentional) order of operations: `%` is executed before `/`,
	// so the division is performed at runtime.
	g_playerHitStudsSoundsIndex = rand() % sizeof(g_playerHitStudsSounds) / sizeof(g_playerHitStudsSounds[0]);
	g_studsHitPlayerSoundsIndex = rand() % sizeof(g_studsHitPlayerSounds) / sizeof(g_studsHitPlayerSounds[0]);
	g_playerHitRhodaSoundsIndex = rand() % sizeof(g_playerHitRhodaSounds) / sizeof(g_playerHitRhodaSounds[0]);
	g_rhodaHitPlayerSoundsIndex = rand() % sizeof(g_rhodaHitPlayerSounds) / sizeof(g_rhodaHitPlayerSounds[0]);
}

// FUNCTION: LEGO1 0x10012e60
// FUNCTION: BETA10 0x100cb191
void LegoRaceCar::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (!m_userNavFlag) {
		if (!LegoCarRaceActor::m_animState) {
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
		LegoCarRaceActor::m_animState = 2;
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
			if (m_animMaps[i]->GetWorldSpeed() == -1.0f) {
				m_skelKick1Anim = m_animMaps[i];
			}
			else if (m_animMaps[i]->GetWorldSpeed() == -2.0f) {
				m_skelKick2Anim = m_animMaps[i];
			}
		}

		assert(m_skelKick1Anim && m_skelKick2Anim);

		// STRING: LEGO1 0x100f0bc4
		m_kick1B = currentWorld->FindPathBoundary("EDG03_44");
		assert(m_kick1B);

		// STRING: LEGO1 0x100f0bb8
		m_kick2B = currentWorld->FindPathBoundary("EDG03_54");
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
void LegoRaceCar::KickCamera(float p_param)
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
		deltaTime = p_param - m_kickStart;

		if (a->GetDuration() <= deltaTime || deltaTime < 0.0) {
			if (m_userState == LEGORACECAR_KICK1) {
				LegoOrientedEdge** edges = m_kick1B->GetEdges();
				m_destEdge = edges[2];
				m_boundary = m_kick1B;
			}
			else {
				LegoOrientedEdge** edges = m_kick1B->GetEdges();
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
			a->GetAnimTreePtr()->GetCamAnim()->CalculateCameraTransform(deltaTime, transformationMatrix);

			if (r->GetCameraController()) {
				r->GetCameraController()->TransformPointOfView(transformationMatrix, 0);
			}

			m_roi->SetLocal2World(transformationMatrix);
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

	m_kickStart = p_param1;
	SoundManager()->GetCacheSoundManager()->Play(g_soundSkel3, NULL, FALSE);

	return TRUE;
}

// FUNCTION: LEGO1 0x100131f0
// FUNCTION: BETA10 0x100cb88a
void LegoRaceCar::Animate(float p_time)
{
	if (m_userNavFlag && (m_userState == LEGORACECAR_KICK1 || m_userState == LEGORACECAR_KICK2)) {
		KickCamera(p_time);
		return;
	}

	LegoCarRaceActor::Animate(p_time);

	if (m_userNavFlag && m_userState == LEGORACECAR_UNKNOWN_1) {
		if (HandleSkeletonKicks(p_time)) {
			return;
		}
	}

	if (LegoCarRaceActor::m_animState == 1) {
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

		// If the player is moving forwards or backwards
		if (absoluteSpeed != 0.0f) {
			g_timePlayerLastMoved = p_time;
			g_playedYouCantStopSound = FALSE;
		}

		// If the player hasn't moved in 5 seconds, play the "you can't stop in the middle of the race!" sound once
		if (p_time - g_timePlayerLastMoved > 5000.0f && !g_playedYouCantStopSound) {
			SoundManager()->GetCacheSoundManager()->Play(g_youCantStopSound, NULL, 0);
			g_playedYouCantStopSound = TRUE;
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
			MxMatrix matr;
			LegoROI* roi = p_actor->GetROI(); // name verified by BETA10 0x100cbbf5
			assert(roi);
			matr = roi->GetLocal2World();

			Vector3(matr[3]) += g_hitOffset;
			roi->SetLocal2World(matr);

			p_actor->SetActorState(c_two);
		}

		if (m_userNavFlag) {
			MxBool actorIsStuds = strcmpi(p_actor->GetROI()->GetName(), "studs") == 0;
			MxBool actorIsRhoda = strcmpi(p_actor->GetROI()->GetName(), "rhoda") == 0;
			MxLong time = Timer()->GetTime();

			const char* soundKey = NULL;

			if (time - g_timeLastRaceCarSoundPlayed > 3000) {
				if (p_bool) {
					if (actorIsStuds) {
						soundKey = g_playerHitStudsSounds[g_playerHitStudsSoundsIndex++];
						if (g_playerHitStudsSoundsIndex >= sizeOfArray(g_playerHitStudsSounds)) {
							g_playerHitStudsSoundsIndex = 0;
						}
					}
					else if (actorIsRhoda) {
						soundKey = g_playerHitRhodaSounds[g_playerHitRhodaSoundsIndex++];
						if (g_playerHitRhodaSoundsIndex >= sizeOfArray(g_playerHitRhodaSounds)) {
							g_playerHitRhodaSoundsIndex = 0;
						}
					}
				}
				else {
					if (actorIsStuds) {
						soundKey = g_studsHitPlayerSounds[g_studsHitPlayerSoundsIndex++];
						if (g_studsHitPlayerSoundsIndex >= sizeOfArray(g_studsHitPlayerSounds)) {
							g_studsHitPlayerSoundsIndex = 0;
						}
					}
					else if (actorIsRhoda) {
						soundKey = g_rhodaHitPlayerSounds[g_rhodaHitPlayerSoundsIndex++];
						if (g_rhodaHitPlayerSoundsIndex >= sizeOfArray(g_rhodaHitPlayerSounds)) {
							g_rhodaHitPlayerSoundsIndex = 0;
						}
					}
				}

				if (soundKey) {
					SoundManager()->GetCacheSoundManager()->Play(soundKey, NULL, FALSE);
					g_timeLastRaceCarSoundPlayed = g_timeLastHitSoundPlayed = time;
				}
			}

			if (p_bool) {
				return m_worldSpeed != 0 ? SUCCESS : FAILURE;
			}
			else {
				return FAILURE;
			}
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
void LegoJetski::InitSoundIndices()
{
	// See note in LegoRaceCar::InitSoundIndices
	g_hitSnapSoundsIndex = rand() % sizeof(g_hitSnapSounds) / sizeof(g_hitSnapSounds[0]);
	g_hitValerieSoundsIndex = rand() % sizeof(g_hitValerieSounds) / sizeof(g_hitValerieSounds[0]);
}

// FUNCTION: LEGO1 0x100136a0
// FUNCTION: BETA10 0x100cbf7e
void LegoJetski::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (!m_userNavFlag) {
		if (!LegoCarRaceActor::m_animState) {
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
		LegoCarRaceActor::m_animState = 2;
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

	if (LegoCarRaceActor::m_animState == 1) {
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
			MxMatrix matr;
			LegoROI* roi = p_actor->GetROI();
			matr = roi->GetLocal2World();

			Vector3(matr[3]) += g_hitOffset;
			roi->SetLocal2World(matr);

			p_actor->SetActorState(c_two);
		}

		if (m_userNavFlag) {
			MxBool actorIsSnap = strcmpi(p_actor->GetROI()->GetName(), "snap") == 0;
			MxBool actorIsValerie = strcmpi(p_actor->GetROI()->GetName(), "valerie") == 0;
			MxLong time = Timer()->GetTime();

			const char* soundKey = NULL;

			if (time - g_timeLastJetskiSoundPlayed > 3000) {
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
					g_timeLastJetskiSoundPlayed = g_timeLastHitSoundPlayed = time;
				}
			}

			if (p_bool) {
				return m_worldSpeed != 0 ? SUCCESS : FAILURE;
			}
			else {
				return FAILURE;
			}
		}
	}

	return SUCCESS;
}
