#include "legoracecar.h"

#include "anim/legoanim.h"
#include "define.h"
#include "legocameracontroller.h"
#include "legorace.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(EdgeReference, 0x08)
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
const EdgeReference* LegoRaceCar::g_pEdgeReferences = g_edgeReferences;

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

	if (m_userState == 2) {
		a = m_unk0x70;
	}
	else {
		// TODO: Possibly an enum?
		const char LEGORACECAR_KICK2 = 4;
		assert(m_userState == LEGORACECAR_KICK2);
		a = m_unk0x74;
	}

	assert(a && a->GetAnimTreePtr() && a->GetAnimTreePtr()->GetCamAnim());

	if (a->GetAnimTreePtr()) {
		deltaTime = p_param - m_unk0x58;

		if (a->GetDuration() <= deltaTime || deltaTime < 0.0) {
			if (m_userState == 2) {
				LegoEdge** edges = m_unk0x78->GetEdges();
				m_destEdge = (LegoUnknown100db7f4*) (edges[2]);
				m_boundary = m_unk0x78;
			}
			else {
				LegoEdge** edges = m_unk0x78->GetEdges();
				m_destEdge = (LegoUnknown100db7f4*) (edges[1]);
				m_boundary = m_unk0x7c;
			}

			m_userState = 0;
		}
		else if (a->GetAnimTreePtr()->GetCamAnim()) {
			MxMatrix transformationMatrix;

			LegoWorld* current_world = CurrentWorld(); // called `r` in BETA10
			assert(current_world);

			transformationMatrix.SetIdentity();

			// Possible bug in the original code: The first argument is not initialized
			a->GetAnimTreePtr()->GetCamAnim()->FUN_1009f490(deltaTime, transformationMatrix);

			if (current_world->GetCamera()) {
				current_world->GetCamera()->FUN_100123e0(transformationMatrix, 0);
			}

			m_roi->FUN_100a58f0(transformationMatrix);
		}
	}
}

// STUB: LEGO1 0x10013130
MxBool LegoRaceCar::FUN_10013130(float)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x100131f0
void LegoRaceCar::VTable0x70(float p_float)
{
	// TODO
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
