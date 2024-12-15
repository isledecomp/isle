#include "act3actors.h"

#include "act3.h"
#include "act3ammo.h"
#include "anim/legoanim.h"
#include "define.h"
#include "legocachesoundmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legopathedgecontainer.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "roi/legoroi.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(Act3Actor, 0x178)
DECOMP_SIZE_ASSERT(Act3Cop, 0x188)
DECOMP_SIZE_ASSERT(Act3Cop::Act3CopDest, 0x20)
DECOMP_SIZE_ASSERT(Act3Brickster, 0x1b4)
DECOMP_SIZE_ASSERT(Act3Shark, 0x1a8)

// name verified by BETA10 0x10018776
// GLOBAL: LEGO1 0x100f4120
// GLOBAL: BETA10 0x101dcdc8
Act3Actor::Act3CopDest g_copDest[5] = {
	{"INT38", NULL, {3.69, -1.31251, -59.231}, {-0.99601698, 0.0, -0.089166}},
	{
		"EDG02_08",
		NULL,
		{
			-96.459999,
			4.0,
			11.22,
		},
		{
			-0.9725,
			0.0,
			-0.23,
		},
	},
	{
		"INT18",
		NULL,
		{
			28.076799,
			2.0,
			32.11,
		},
		{
			-0.19769999,
			0.0,
			0.98,
		},
	},
	{
		"INT48",
		NULL,
		{
			84.736,
			9.0,
			-1.965,
		},
		{
			0.241,
			0.0,
			-0.97,
		},
	},
	{"INT42",
	 NULL,
	 {
		 63.76178,
		 0.999993,
		 -77.739998,
	 },
	 {
		 0.47999999,
		 0.0,
		 -0.87699997,
	 }}
};

// Initialized at LEGO1 0x1003fa20
// GLOBAL: LEGO1 0x10104ef0
Mx3DPointFloat Act3Actor::g_unk0x10104ef0 = Mx3DPointFloat(0.0, 5.0, 0.0);

// FUNCTION: LEGO1 0x1003fa50
Act3Actor::Act3Actor()
{
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x1003fb70
// FUNCTION: BETA10 0x100180ab
MxU32 Act3Actor::VTable0x90(float p_time, Matrix4& p_transform)
{
	// Note: Code duplication with LegoExtraActor::VTable0x90
	switch (m_actorState & c_maxState) {
	case c_initial:
	case c_one:
		return TRUE;
	case c_two:
		m_unk0x1c = p_time + 2000.0f;
		m_actorState = c_three;
		m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
		m_lastTime = p_time;
		return FALSE;
	case c_three:
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
			m_actorState = c_initial;
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
// FUNCTION: BETA10 0x10018328
MxResult Act3Actor::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_actor->GetUserNavFlag() && p_bool) {
		if (p_actor->GetActorState() != c_initial) {
			return FAILURE;
		}

		LegoROI* roi = p_actor->GetROI();

		MxMatrix local2world;
		local2world = roi->GetLocal2World();

		Vector3(local2world[3]) += g_unk0x10104ef0;

		roi->FUN_100a58f0(local2world);
		roi->VTable0x14();

		p_actor->SetActorState(c_two | c_noCollide);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1003fe30
// FUNCTION: BETA10 0x10018412
Act3Cop::Act3Cop()
{
	m_unk0x20 = -1.0f;
	m_world = NULL;
	SetActorState(c_disabled);
}

// FUNCTION: LEGO1 0x1003ff70
// FUNCTION: BETA10 0x10018526
MxResult Act3Cop::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	LegoROI* roi = p_actor->GetROI();

	if (p_bool && !strncmp(roi->GetName(), "dammo", 5)) {
		MxS32 index = -1;
		if (sscanf(roi->GetName(), "dammo%d", &index) != 1) {
			assert(0);
		}

		assert(m_world);
		((Act3*) m_world)->EatDonut(index);
		m_unk0x20 = m_lastTime + 2000;
		SetWorldSpeed(6.0);

		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("eatdn", NULL, FALSE);
		FUN_10040360();
	}
	else {
		if (((Act3*) m_world)->m_brickster->GetROI() != roi) {
			if (p_bool) {
				return Act3Actor::HitActor(p_actor, p_bool);
			}
		}
		else {
			((Act3*) m_world)->GoodEnding(roi->GetLocal2World());
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10040060
// FUNCTION: BETA10 0x100186fa
void Act3Cop::ParseAction(char* p_extra)
{
	m_world = CurrentWorld();
	LegoAnimActor::ParseAction(p_extra);
	((Act3*) m_world)->AddCop(this);
	Act3* world = (Act3*) m_world;
	MxS32 i;

	// The typecast is necessary for correct signedness
	for (i = 0; i < (MxS32) sizeOfArray(g_copDest); i++) {
		assert(g_copDest[i].m_bName);
		g_copDest[i].m_boundary = world->FindPathBoundary(g_copDest[i].m_bName);
		assert(g_copDest[i].m_boundary);

		if (g_copDest[i].m_boundary) {
			Mx3DPointFloat point(g_copDest[i].m_unk0x08[0], g_copDest[i].m_unk0x08[1], g_copDest[i].m_unk0x08[2]);
			LegoPathBoundary* boundary = g_copDest[i].m_boundary;

			for (MxS32 j = 0; j < boundary->GetNumEdges(); j++) {
				Mx4DPointFloat* edgeNormal = boundary->GetEdgeNormal(j);
				if (point.Dot(edgeNormal, &point) + edgeNormal->index_operator(3) < -0.001) {
					MxTrace("Bad Act3 cop destination %d\n", i);
					break;
				}
			}

			Mx4DPointFloat* boundary0x14 = boundary->GetUnknown0x14();

			if (point.Dot(&point, boundary0x14) + boundary0x14->index_operator(3) <= 0.001 &&
				point.Dot(&point, boundary0x14) + boundary0x14->index_operator(3) >= -0.001) {
				continue;
			}

			g_copDest[i].m_unk0x08[1] = -(boundary0x14->index_operator(3) + boundary0x14->index_operator(0) * point[0] +
										  boundary0x14->index_operator(2) * point[2]) /
										boundary0x14->index_operator(1);

			MxTrace(
				"Act3 cop destination %d (%g, %g, %g) is not on plane of boundary %s...adjusting to (%g, %g, %g)\n",
				i,
				point[0],
				point[1],
				point[2],
				boundary->GetName(),
				point[0],
				g_copDest[i].m_unk0x08[1],
				point[2]
			);
		}
	}

	for (i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]->GetUnknown0x00() == -1.0f) {
			m_eatAnim = m_animMaps[i];
		}
	}

	assert(m_eatAnim);
}

// FUNCTION: LEGO1 0x100401f0
// FUNCTION: BETA10 0x10018abf
void Act3Cop::Animate(float p_time)
{
	Act3Actor::Animate(p_time);

	if (m_unk0x20 > 0.0f && m_unk0x20 < m_lastTime) {
		SetWorldSpeed(2.0f);
		m_unk0x20 = -1.0f;
	}

	Act3Brickster* brickster = ((Act3*) m_world)->m_brickster;

	if (brickster != NULL && brickster->GetROI() != NULL && m_roi != NULL) {
		Mx3DPointFloat local34(brickster->GetROI()->GetLocal2World()[3]);
		local34 -= m_roi->GetLocal2World()[3];

		float distance = local34.LenSquared();

		if (distance < 4.0f) {
			((Act3*) m_world)->GoodEnding(brickster->GetROI()->GetLocal2World());
			return;
		}

		if (distance < 25.0f) {
			brickster->SetActorState(c_disabled);
			FUN_10040360();
			return;
		}
	}

	if (m_grec == NULL) {
		FUN_10040360();
	}
}

// FUNCTION: LEGO1 0x10040350
// FUNCTION: BETA10 0x10018c4a
MxResult Act3Cop::FUN_10040350(Act3Ammo& p_ammo, const Vector3&)
{
	return FUN_10040360();
}

// STUB: LEGO1 0x10040360
// STUB: BETA10 0x10018c6a
MxResult Act3Cop::FUN_10040360()
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10040d20
// FUNCTION: BETA10 0x1001942c
MxResult Act3Cop::VTable0x9c()
{
	if (m_grec && !m_grec->GetBit1()) {
		delete m_grec;
		m_grec = NULL;
		m_lastTime = Timer()->GetTime();
		FUN_10040360();
		return SUCCESS;
	}

	return Act3Actor::VTable0x9c();
}

// FUNCTION: LEGO1 0x10040e10
// FUNCTION: BETA10 0x10019516
Act3Brickster::Act3Brickster()
{
	m_world = NULL;
	m_unk0x2c = 0;
	m_unk0x30 = 0;
	m_shootAnim = NULL;
	m_unk0x38 = 0;
	m_unk0x20 = 0.0f;
	m_unk0x24 = 0.0f;
	m_unk0x54 = 0;

	SetActorState(c_disabled);
	m_unk0x58 = 0;

	m_unk0x3c.Clear();
}

// FUNCTION: LEGO1 0x10040f20
// FUNCTION: BETA10 0x10019663
Act3Brickster::~Act3Brickster()
{
	// empty
}

// FUNCTION: LEGO1 0x10040ff0
// FUNCTION: BETA10 0x100196ff
void Act3Brickster::ParseAction(char* p_extra)
{
	m_world = CurrentWorld();

	LegoAnimActor::ParseAction(p_extra);

	((Act3*) m_world)->SetBrickster(this);

	for (MxS32 i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]->GetUnknown0x00() == -1.0f) {
			m_shootAnim = m_animMaps[i];
		}
	}

	assert(m_shootAnim);
}

// STUB: LEGO1 0x10041050
// STUB: BETA10 0x100197d7
void Act3Brickster::Animate(float p_time)
{
	// TODO
}

// FUNCTION: LEGO1 0x100416b0
// FUNCTION: BETA10 0x1001a299
MxResult Act3Brickster::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_bool) {
		return FAILURE;
	}

	Act3* a3 = (Act3*) m_world;
	LegoROI* r = p_actor->GetROI();
	assert(r);

	if (a3->m_cop1->GetROI() != r && a3->m_cop2->GetROI() != r) {
		if (!strncmp(r->GetName(), "pammo", 5)) {
			MxS32 index = -1;
			if (sscanf(r->GetName(), "pammo%d", &index) != 1) {
				assert(0);
			}

			assert(m_world);

			if (a3->m_pizzas[index].IsValid() && !a3->m_pizzas[index].IsBit5()) {
				a3->EatPizza(index);
			}

			m_unk0x38 = 2;
			return SUCCESS;
		}
		else {
			return Act3Actor::HitActor(p_actor, p_bool);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100417a0
// FUNCTION: BETA10 0x1001a3cf
MxResult Act3Brickster::FUN_100417a0(Act3Ammo& p_ammo, const Vector3&)
{
	if (m_unk0x58 < 8) {
		return FUN_100417c0();
	}

	return SUCCESS;
}

// STUB: LEGO1 0x100417c0
// STUB: BETA10 0x1001a407
MxResult Act3Brickster::FUN_100417c0()
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10042990
// FUNCTION: BETA10 0x1001b6e2
void Act3Brickster::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	if (m_unk0x38 != 8) {
		m_boundary->SwitchBoundary(this, p_boundary, p_edge, p_unk0xe4);
	}
}

// FUNCTION: LEGO1 0x100429d0
// FUNCTION: BETA10 0x1001b75b
MxResult Act3Brickster::VTable0x9c()
{
	if (m_grec && !m_grec->GetBit1()) {
		delete m_grec;
		m_grec = NULL;
		m_lastTime = Timer()->GetTime();
		return SUCCESS;
	}

	return Act3Actor::VTable0x9c();
}

// FUNCTION: LEGO1 0x10042ab0
Act3Shark::Act3Shark()
{
	m_unk0x2c = 0.0f;
	m_unk0x28 = NULL;
}

// FUNCTION: LEGO1 0x10042ce0
MxResult Act3Shark::FUN_10042ce0(Act3Ammo* p_ammo)
{
	p_ammo->SetBit5(TRUE);
	m_unk0x1c.push_back(p_ammo);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10042d40
void Act3Shark::Animate(float p_time)
{
	LegoROI** roiMap = m_unk0x34->GetROIMap();

	if (m_unk0x28 == NULL) {
		if (m_unk0x1c.size() > 0) {
			m_unk0x28 = m_unk0x1c.front();
			m_unk0x1c.pop_front();
			m_unk0x2c = p_time;
			roiMap[1] = m_unk0x28->GetROI();
			m_unk0x3c = roiMap[1]->GetLocal2World()[3];
			roiMap[1]->SetVisibility(TRUE);
			roiMap[2]->SetVisibility(TRUE);
		}

		if (m_unk0x28 == NULL) {
			return;
		}
	}

	float time = m_unk0x2c + m_unk0x34->GetDuration();

	if (time > p_time) {
		float duration = p_time - m_unk0x2c;

		if (duration < 0) {
			duration = 0;
		}

		if (m_unk0x34->GetDuration() < duration) {
			duration = m_unk0x34->GetDuration();
		}

		MxMatrix mat;
		mat.SetIdentity();

		Vector3 vec(mat[3]);
		vec = m_unk0x3c;

		LegoTreeNode* node = m_unk0x34->GetAnimTreePtr()->GetRoot();
		LegoROI::FUN_100a8e80(node, mat, duration, m_unk0x34->GetROIMap());
	}
	else {
		roiMap[1] = m_unk0x38;
		((Act3*) m_world)->RemovePizza(*m_unk0x28);
		m_unk0x28 = NULL;
		roiMap[1]->SetVisibility(FALSE);
		roiMap[2]->SetVisibility(FALSE);
	}
}

// FUNCTION: LEGO1 0x10042f30
void Act3Shark::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	m_world = CurrentWorld();

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
