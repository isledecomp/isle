#include "act3actors.h"

#include "act3.h"
#include "act3ammo.h"
#include "define.h"
#include "legocachesoundmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxutilities.h"
#include "roi/legoroi.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(Act3Actor, 0x178)
DECOMP_SIZE_ASSERT(Act3Cop, 0x188)
DECOMP_SIZE_ASSERT(Act3Brickster, 0x1b4)
DECOMP_SIZE_ASSERT(Act3Shark, 0x1a8)

// Initialized at LEGO1 0x1003fa20
// GLOBAL: LEGO1 0x10104ef0
Mx3DPointFloat Act3Actor::g_unk0x10104ef0 = Mx3DPointFloat(0.0, 5.0, 0.0);

// FUNCTION: LEGO1 0x1003fa50
Act3Actor::Act3Actor()
{
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x1003fb70
MxU32 Act3Actor::VTable0x90(float p_time, Matrix4& p_transform)
{
	// Note: Code duplication with LegoExtraActor::VTable0x90
	switch (m_state & 0xff) {
	case 0:
	case 1:
		return TRUE;
	case 2:
		m_unk0x1c = p_time + 2000.0f;
		m_state = 3;
		m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
		m_lastTime = p_time;
		return FALSE;
	case 3:
		assert(!m_userNavFlag);
		Vector3 positionRef(p_transform[3]);

		p_transform = m_roi->GetLocal2World();

		if (m_unk0x1c > p_time) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			p_transform.RotateX(0.6);
			positionRef = position;

			m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
			m_lastTime = p_time;

			VTable0x74(p_transform);
			return FALSE;
		}
		else {
			m_state = 0;
			m_unk0x1c = 0;

			positionRef -= g_unk0x10104ef0;
			m_roi->FUN_100a58f0(p_transform);
			m_roi->VTable0x14();
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1003fd90
MxResult Act3Actor::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_actor->GetUserNavFlag() && p_bool) {
		if (p_actor->GetState()) {
			return FAILURE;
		}

		LegoROI* roi = p_actor->GetROI();

		MxMatrix local2world;
		local2world = roi->GetLocal2World();

		Vector3(local2world[3]) += g_unk0x10104ef0;

		roi->FUN_100a58f0(local2world);
		roi->VTable0x14();

		p_actor->SetState(c_bit2 | c_bit9);
	}

	return SUCCESS;
}

// STUB: LEGO1 0x1003fe30
Act3Cop::Act3Cop()
{
	// TODO
}

// FUNCTION: LEGO1 0x1003ff70
// FUNCTION: BETA10 0x10018526
MxResult Act3Cop::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	LegoROI* roi = p_actor->GetROI();
	if (p_bool && !strncmp(roi->GetName(), "dammo", 5)) {
		MxS32 count = -1;
		if (sscanf(roi->GetName(), "dammo%d", &count) != 1) {
			assert(0);
		}

		assert(m_world);
		((Act3*) m_world)->EatDonut(count);
		m_unk0x20 = m_lastTime + 2000;
		SetWorldSpeed(6.0);

		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("eatdn", NULL, FALSE);
		FUN_10040360();
	}
	else {
		if (((Act3*) m_world)->GetBrickster()->GetROI() != roi) {
			if (p_bool) {
				return Act3Actor::VTable0x94(p_actor, p_bool);
			}
		}
		else {
			((Act3*) m_world)->GoodEnding(roi->GetLocal2World());
		}
	}

	return SUCCESS;
}

// STUB: LEGO1 0x10040060
void Act3Cop::ParseAction(char* p_extra)
{
	// TODO
}

// STUB: LEGO1 0x100401f0
void Act3Cop::VTable0x70(float p_time)
{
	// TODO
}

// STUB: LEGO1 0x10040360
// STUB: BETA10 0x10018c6a
void Act3Cop::FUN_10040360()
{
	// TODO
}

// STUB: LEGO1 0x10040d20
MxResult Act3Cop::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10040e10
Act3Brickster::Act3Brickster()
{
	// TODO
}

// FUNCTION: LEGO1 0x10040f20
Act3Brickster::~Act3Brickster()
{
	// TODO
}

// STUB: LEGO1 0x10040ff0
void Act3Brickster::ParseAction(char* p_extra)
{
	// TODO
}

// STUB: LEGO1 0x10041050
void Act3Brickster::VTable0x70(float p_time)
{
	// TODO
}

// STUB: LEGO1 0x100416b0
MxResult Act3Brickster::VTable0x94(LegoPathActor*, MxBool)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100417c0
// STUB: BETA10 0x1001a407
MxResult Act3Brickster::FUN_100417c0()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10042990
void Act3Brickster::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	// TODO
}

// STUB: LEGO1 0x100429d0
MxResult Act3Brickster::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10042ab0
Act3Shark::Act3Shark()
{
	m_unk0x2c = 0.0f;
	m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x10042ce0
MxResult Act3Shark::FUN_10042ce0(Act3Ammo* p_ammo)
{
	p_ammo->SetBit5(TRUE);
	m_unk0x1c.push_back(p_ammo);
	return SUCCESS;
}

// STUB: LEGO1 0x10042d40
void Act3Shark::VTable0x70(float p_time)
{
	// TODO
}

// FUNCTION: LEGO1 0x10042f30
void Act3Shark::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	m_world = (LegoWorld*) CurrentWorld();

	char value[256];
	if (KeyValueStringParse(value, g_strANIMATION, p_extra)) {
		char* token = strtok(value, g_parseExtraTokens);

		while (token != NULL) {
			LegoLocomotionAnimPresenter* presenter =
				(LegoLocomotionAnimPresenter*) m_world->Find("LegoAnimPresenter", token);

			if (presenter != NULL) {
				token = strtok(NULL, g_parseExtraTokens);

				if (token != NULL) {
					presenter->FUN_1006d680(this, atof(token));
				}
			}

			token = strtok(NULL, g_parseExtraTokens);
		}
	}

	((Act3*) m_world)->SetShark(this);
	m_unk0x34 = m_animMaps[0];
	m_unk0x38 = m_unk0x34->m_roiMap[1];
	m_unk0x38->SetVisibility(FALSE);
	m_world->PlaceActor(this);
}
