#include "act3actors.h"

#include "act3.h"
#include "act3ammo.h"
#include "anim/legoanim.h"
#include "define.h"
#include "legoanimpresenter.h"
#include "legobuildingmanager.h"
#include "legocachesoundmanager.h"
#include "legopathedgecontainer.h"
#include "legoplantmanager.h"
#include "legoplants.h"
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
Act3Cop::Act3CopDest g_copDest[5] = {
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
// FUNCTION: BETA10 0x10017fb8
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
			m_roi->SetLocal2World(p_transform);
			m_roi->WrappedUpdateWorldData();
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

		roi->SetLocal2World(local2world);
		roi->WrappedUpdateWorldData();

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
				if (point.Dot(*edgeNormal, point) + edgeNormal->index_operator(3) < -0.001) {
					MxTrace("Bad Act3 cop destination %d\n", i);
					break;
				}
			}

			Mx4DPointFloat* boundary0x14 = boundary->GetUp();

			if (point.Dot(point, *boundary0x14) + boundary0x14->index_operator(3) <= 0.001 &&
				point.Dot(point, *boundary0x14) + boundary0x14->index_operator(3) >= -0.001) {
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
		if (m_animMaps[i]->GetWorldSpeed() == -1.0f) {
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

// FUNCTION: LEGO1 0x10040360
// FUNCTION: BETA10 0x10018c6a
MxResult Act3Cop::FUN_10040360()
{
	LegoPathEdgeContainer* grec = NULL;
	Act3* a3 = (Act3*) m_world;

	MxMatrix local74(m_unk0xec);
	Vector3 local2c(local74[3]);
	Vector3 local20(local74[2]);

	Mx3DPointFloat local7c;
	local7c = a3->m_brickster->GetROI()->GetLocal2World()[3];
	local7c -= local2c;

	if (local7c.LenSquared() < 144.0f) {
		local7c = a3->m_brickster->GetROI()->GetLocal2World()[3];
		Mx3DPointFloat local5c(a3->m_brickster->GetROI()->GetLocal2World()[2]);
		LegoPathBoundary* boundary = a3->m_brickster->GetBoundary();

		grec = new LegoPathEdgeContainer();
		assert(grec);

		MxFloat local34;
		if (m_pathController->FUN_10048310(
				grec,
				local2c,
				local20,
				m_boundary,
				local7c,
				local5c,
				boundary,
				LegoOrientedEdge::c_bit1,
				&local34
			) != SUCCESS) {
			delete grec;
			grec = NULL;
		}
	}

	if (grec == NULL) {
		float local18;

		for (MxS32 i = 0; i < MAX_DONUTS; i++) {
			Act3Ammo* donut = &a3->m_donuts[i];
			assert(donut);

			if (donut->IsValid() && donut->GetActorState() == c_initial) {
				LegoROI* proi = donut->GetROI();
				assert(proi);

				MxMatrix locald0 = proi->GetLocal2World();
				Vector3 local88(locald0[3]);
				Mx3DPointFloat localec(local88);
				localec -= local88;

				LegoPathEdgeContainer* r2 = new LegoPathEdgeContainer();
				assert(r2);

				MxFloat locald8;
				LegoPathEdgeContainer *local138, *local134, *local140, *local13c; // unused

				if (m_pathController->FUN_10048310(
						r2,
						local2c,
						local20,
						m_boundary,
						local88,
						localec,
						donut->GetBoundary(),
						LegoOrientedEdge::c_bit1,
						&locald8
					) == SUCCESS &&
					(grec == NULL || locald8 < local18)) {
					if (grec != NULL) {
						local134 = local138 = grec;
						delete grec;
					}

					grec = r2;
					local18 = locald8;
				}

				if (grec != r2) {
					local13c = local140 = r2;
					delete r2;
				}
			}
		}

		if (grec == NULL) {
			MxS32 random = rand() % (MxS32) sizeOfArray(g_copDest);
			Vector3 localf8(g_copDest[random].m_unk0x08);
			Vector3 local108(g_copDest[random].m_unk0x14);

			grec = new LegoPathEdgeContainer();
			LegoPathBoundary* boundary = g_copDest[random].m_boundary;

			if (boundary != NULL) {
				MxFloat local100;
				LegoPathEdgeContainer *local150, *local14c; // unused

				if (m_pathController->FUN_10048310(
						grec,
						local2c,
						local20,
						m_boundary,
						localf8,
						local108,
						boundary,
						LegoOrientedEdge::c_bit1,
						&local100
					) != SUCCESS) {
					local14c = local150 = grec;
					delete grec;
					grec = NULL;
				}
			}
		}
	}

	if (grec != NULL) {
		LegoPathEdgeContainer *local158, *local154; // unused
		if (m_grec != NULL) {
			local154 = local158 = m_grec;
			delete m_grec;
		}

		m_grec = grec;
		Mx3DPointFloat vecUnk;

		if (m_grec->size() == 0) {
			vecUnk = m_grec->m_position;
			m_boundary = m_grec->m_boundary;

			m_grec->m_direction = m_unk0xec[3];
			m_grec->m_direction -= vecUnk;
		}
		else {
			Mx3DPointFloat local128;
			LegoEdge* edge = m_grec->back().m_edge;

			Vector3* v1 = edge->CWVertex(*m_grec->m_boundary);
			Vector3* v2 = edge->CCWVertex(*m_grec->m_boundary);
			assert(v1 && v2);

			local128 = *v2;
			local128 -= *v1;
			local128 *= m_unk0xe4;
			local128 += *v1;
			local128 *= -1.0f;
			local128 += m_grec->m_position;
			local128.Unitize();
			m_grec->m_direction = local128;

			edge = m_grec->front().m_edge;
			LegoPathBoundary* boundary = m_grec->front().m_boundary;

			v1 = edge->CWVertex(*boundary);
			v2 = edge->CCWVertex(*boundary);

			vecUnk = *v2;
			vecUnk -= *v1;
			vecUnk *= m_unk0xe4;
			vecUnk += *v1;
		}

		Vector3 v1(m_unk0xec[0]);
		Vector3 v2(m_unk0xec[1]);
		Vector3 v3(m_unk0xec[2]);
		Vector3 v4(m_unk0xec[3]);

		v3 = v4;
		v3 -= vecUnk;
		v3.Unitize();
		v1.EqualsCross(v2, v3);
		v1.Unitize();
		v2.EqualsCross(v3, v1);

		VTable0x9c();
	}

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
	m_pInfo = NULL;
	m_bInfo = NULL;
	m_shootAnim = NULL;
	m_unk0x38 = 0;
	m_unk0x20 = 0.0f;
	m_unk0x24 = 0.0f;
	m_unk0x54 = 0.0f;

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
		if (m_animMaps[i]->GetWorldSpeed() == -1.0f) {
			m_shootAnim = m_animMaps[i];
		}
	}

	assert(m_shootAnim);
}

// FUNCTION: LEGO1 0x10041050
// FUNCTION: BETA10 0x100197d7
void Act3Brickster::Animate(float p_time)
{
	if (m_lastTime <= m_unk0x20 && m_unk0x20 <= p_time) {
		SetWorldSpeed(5.0f);
	}

	if (m_unk0x38 != 3 && m_unk0x38 != 4) {
		Act3Actor::Animate(p_time);
	}

	if (m_unk0x54 < p_time) {
		((Act3*) m_world)->TriggerHitSound(5);
		m_unk0x54 = p_time + 15000.0f;
	}

	switch (m_unk0x38) {
	case 1:
		FUN_100417c0();
		break;
	case 2:
		m_unk0x58++;
		m_unk0x20 = p_time + 2000.0f;
		SetWorldSpeed(3.0f);

		assert(SoundManager()->GetCacheSoundManager());

		if (m_unk0x58 >= 8) {
			((Act3*) m_world)->TriggerHitSound(6);
		}
		else {
			SoundManager()->GetCacheSoundManager()->Play("eatpz", NULL, FALSE);
		}

		FUN_100417c0();
		break;
	case 3:
		assert(m_shootAnim && m_pInfo);

		if (m_unk0x50 < p_time) {
			while (m_pInfo->m_counter) {
				PlantManager()->DecrementCounter(m_pInfo->m_entity);
			}

			assert(SoundManager()->GetCacheSoundManager());
			SoundManager()->GetCacheSoundManager()->Play("thpt", NULL, FALSE);
			m_unk0x58 = 0;
			FUN_100417c0();
		}
		else {
			MxMatrix local70;
			local70 = m_unk0xec;

			Vector3 local14(local70[0]);
			Vector3 local28(local70[1]);
			Vector3 localc(local70[2]);
			Vector3 local20(local70[3]);

			localc = local20;
			localc -= m_pInfo->m_position;
			localc.Unitize();
			local14.EqualsCross(local28, localc);
			local14.Unitize();
			local28.EqualsCross(localc, local14);

			assert(!m_cameraFlag);

			LegoTreeNode* root = m_shootAnim->GetAnimTreePtr()->GetRoot();
			float time = p_time - (m_unk0x50 - m_shootAnim->GetDuration());

			for (MxS32 i = 0; i < root->GetNumChildren(); i++) {
				LegoROI::ApplyAnimationTransformation(root->GetChild(i), local70, time, m_shootAnim->GetROIMap());
			}
		}

		m_lastTime = p_time;
		break;
	case 4:
		assert(m_shootAnim && m_bInfo);

		if (m_unk0x50 < p_time) {
			((Act3*) m_world)->FUN_10073a60();
			m_unk0x58 = 0;
			assert(SoundManager()->GetCacheSoundManager());
			SoundManager()->GetCacheSoundManager()->Play("thpt", NULL, FALSE);

			while (m_bInfo->m_counter > 0 || m_bInfo->m_counter == -1) {
				if (!BuildingManager()->DecrementCounter(m_bInfo)) {
					break;
				}
			}

			FUN_100417c0();
		}
		else {
			MxMatrix locale4;
			locale4 = m_unk0xec;

			Vector3 local88(locale4[0]);
			Vector3 local9c(locale4[1]);
			Vector3 local80(locale4[2]);
			Vector3 local94(locale4[3]);

			local80 = local94;
			assert(m_bInfo->m_entity && m_bInfo->m_entity->GetROI());

			local80 -= m_unk0x3c;
			local80.Unitize();
			local88.EqualsCross(local9c, local80);
			local88.Unitize();
			local9c.EqualsCross(local80, local88);

			assert(!m_cameraFlag);

			LegoTreeNode* root = m_shootAnim->GetAnimTreePtr()->GetRoot();
			float time = p_time - (m_unk0x50 - m_shootAnim->GetDuration());

			for (MxS32 i = 0; i < root->GetNumChildren(); i++) {
				LegoROI::ApplyAnimationTransformation(root->GetChild(i), locale4, time, m_shootAnim->GetROIMap());
			}
		}

		m_lastTime = p_time;
		break;
	case 5:
		if (m_grec == NULL) {
			assert(m_shootAnim && m_pInfo);
			m_unk0x38 = 3;
			m_unk0x50 = p_time + m_shootAnim->GetDuration();
			assert(SoundManager()->GetCacheSoundManager());
			SoundManager()->GetCacheSoundManager()->Play("xarrow", NULL, FALSE);
		}
		else {
			FUN_10042300();
		}
		break;
	case 6:
		if (m_grec == NULL) {
			assert(m_shootAnim && m_bInfo);
			m_unk0x38 = 4;
			m_unk0x50 = p_time + m_shootAnim->GetDuration();
			assert(SoundManager()->GetCacheSoundManager());
			SoundManager()->GetCacheSoundManager()->Play("xarrow", NULL, FALSE);
			BuildingManager()->ScheduleAnimation(m_bInfo->m_entity, 0, FALSE, TRUE);
			m_unk0x3c = m_bInfo->m_entity->GetROI()->GetLocal2World()[3];
		}
		else {
			FUN_10042300();
		}
		break;
	case 7:
	default:
		FUN_10042300();
		break;
	case 8:
		m_unk0x24 = p_time + 10000.0f;
		m_unk0x38 = 9;
		break;
	case 9:
		if (m_unk0x24 < p_time) {
			FUN_100417c0();
		}
		else if (m_unk0x24 - 9000.0f < p_time) {
			FUN_10042300();
		}
		break;
	}
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

			if (a3->m_pizzas[index].IsValid() && !a3->m_pizzas[index].IsSharkFood()) {
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

// FUNCTION: LEGO1 0x100417c0
// FUNCTION: BETA10 0x1001a407
MxResult Act3Brickster::FUN_100417c0()
{
	m_pInfo = NULL;
	m_bInfo = NULL;
	m_unk0x38 = 0;
	LegoPathEdgeContainer* grec = NULL;
	Act3* a3 = (Act3*) m_world;

	MxMatrix local70(m_unk0xec);
	Vector3 local28(local70[3]);
	Vector3 local20(local70[2]);

	if (m_unk0x58 < 8 && m_unk0x24 + 5000.0f < m_lastTime) {
		float local18;

		for (MxS32 i = 0; i < MAX_PIZZAS; i++) {
			Act3Ammo* pizza = &a3->m_pizzas[i];
			assert(pizza);

			if (pizza->IsValid() && !pizza->IsSharkFood() && pizza->GetActorState() == c_initial) {
				LegoROI* proi = pizza->GetROI();
				assert(proi);

				MxMatrix locald0 = proi->GetLocal2World();
				Vector3 local88(locald0[3]);
				Mx3DPointFloat localec(local88);
				localec -= local28;

				if (localec.LenSquared() > 1600.0f) {
					((Act3*) m_world)->m_shark->EatPizza(pizza);
				}
				else {
					LegoPathEdgeContainer* r2 = new LegoPathEdgeContainer();
					assert(r2);

					MxFloat locald8;
					LegoPathEdgeContainer *local16c, *local168, *local174, *local170; // unused

					if (m_pathController->FUN_10048310(
							r2,
							local28,
							local20,
							m_boundary,
							local88,
							localec,
							pizza->GetBoundary(),
							LegoOrientedEdge::c_bit1,
							&locald8
						) == SUCCESS &&
						(grec == NULL || locald8 < local18)) {
						if (grec != NULL) {
							local168 = local16c = grec;
							delete grec;
						}

						grec = r2;
						local18 = locald8;
					}

					if (grec != r2) {
						local170 = local174 = r2;
						delete r2;
					}
				}
			}
		}
	}

	if (grec == NULL) {
		MxS32 length = 0;
		LegoPlantInfo* pInfo = PlantManager()->GetInfoArray(length);
		Mx3DPointFloat local108;
		Mx3DPointFloat local138;
		MxS32 local120 = -1;
		MxU32 local110 = FALSE;
		LegoPathBoundary* localf4 = NULL;
		LegoBuildingInfo* bInfo = BuildingManager()->GetInfoArray(length);
		float local124;

		for (MxS32 i = 0; i < length; i++) {
			if (bInfo[i].m_counter < 0 && bInfo[i].m_boundary != NULL && bInfo[i].m_entity != NULL && i != 0 &&
				(local120 == -1 || i != 15)) {
				Mx3DPointFloat local188(bInfo[i].m_x, bInfo[i].m_y, bInfo[i].m_z);

				local138 = local188;
				local138 -= local28;
				float length = local138.LenSquared();

				if (local120 < 0 || length < local124) {
					local110 = TRUE;
					local120 = i;
					local124 = length;
				}
			}
		}

		if (local120 != -1) {
			if (local110) {
				m_bInfo = &bInfo[local120];
				localf4 = m_bInfo->m_boundary;
				Mx3DPointFloat local19c(m_bInfo->m_x, m_bInfo->m_y, m_bInfo->m_z);
				local108 = local19c;
			}
			else {
				m_pInfo = &pInfo[local120];
				localf4 = m_pInfo->m_boundary;
				Mx3DPointFloat local1b0(m_pInfo->m_x, m_pInfo->m_y, m_pInfo->m_z);
				local108 = local1b0;
			}
		}

		if (localf4 != NULL) {
			assert(m_pInfo || m_bInfo);

			grec = new LegoPathEdgeContainer();
			local138 = local108;
			local138 -= local28;
			local138.Unitize();

			MxFloat local13c;
			LegoPathEdgeContainer *local1c0, *local1bc; // unused

			if (m_pathController->FUN_10048310(
					grec,
					local28,
					local20,
					m_boundary,
					local108,
					local138,
					localf4,
					LegoOrientedEdge::c_bit1,
					&local13c
				) != SUCCESS) {
				local1bc = local1c0 = grec;

				if (grec != NULL) {
					delete grec;
				}

				grec = NULL;
				assert(0);
			}
		}
		else {
			((Act3*) m_world)->BadEnding(m_roi->GetLocal2World());
			return SUCCESS;
		}
	}

	if (grec != NULL) {
		Mx3DPointFloat local150;

		LegoPathEdgeContainer *local1c4, *local1c8; // unused
		if (m_grec != NULL) {
			local1c4 = local1c8 = m_grec;
			delete m_grec;
		}

		m_grec = grec;
		Mx3DPointFloat vecUnk;

		if (m_grec->size() == 0) {
			vecUnk = m_grec->m_position;
			m_boundary = m_grec->m_boundary;

			m_grec->m_direction = m_unk0xec[3];
			m_grec->m_direction -= vecUnk;

			local150 = m_grec->m_direction;
		}
		else {
			LegoEdge* edge = m_grec->back().m_edge;

			Vector3* v1 = edge->CWVertex(*m_grec->m_boundary);
			Vector3* v2 = edge->CCWVertex(*m_grec->m_boundary);
			assert(v1 && v2);

			local150 = *v2;
			local150 -= *v1;
			local150 *= m_unk0xe4;
			local150 += *v1;
			local150 *= -1.0f;
			local150 += m_grec->m_position;
			local150.Unitize();
			m_grec->m_direction = local150;

			edge = m_grec->front().m_edge;
			LegoPathBoundary* boundary = m_grec->front().m_boundary;

			v1 = edge->CWVertex(*boundary);
			v2 = edge->CCWVertex(*boundary);

			vecUnk = *v2;
			vecUnk -= *v1;
			vecUnk *= m_unk0xe4;
			vecUnk += *v1;
		}

		Vector3 v1(m_unk0xec[0]);
		Vector3 v2(m_unk0xec[1]);
		Vector3 v3(m_unk0xec[2]);
		Vector3 v4(m_unk0xec[3]);

		v3 = v4;
		v3 -= vecUnk;
		v3.Unitize();
		v1.EqualsCross(v2, v3);
		v1.Unitize();
		v2.EqualsCross(v3, v1);

		VTable0x9c();

		if (m_pInfo != NULL) {
			m_unk0x38 = 5;
		}
		else if (m_bInfo != NULL) {
			m_unk0x38 = 6;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10042300
// FUNCTION: BETA10 0x1001b017
MxS32 Act3Brickster::FUN_10042300()
{
	Act3* a3 = (Act3*) m_world;

	assert(a3 && a3->m_cop1 && a3->m_cop2);
	assert(a3->m_cop1->GetROI() && a3->m_cop2->GetROI() && GetROI());

	Mx3DPointFloat local64[2];
	Mx3DPointFloat local38;
	Mx3DPointFloat local18;

	MxS32 local1c = 0;
	float local24[2];

	local64[0] = a3->m_cop1->GetROI()->GetLocal2World()[3];
	local64[1] = a3->m_cop2->GetROI()->GetLocal2World()[3];
	local38 = GetROI()->GetLocal2World()[3];

	local18 = local64[0];
	local18 -= local38;
	local24[0] = local18.LenSquared();

	local18 = local64[1];
	local18 -= local38;
	local24[1] = local18.LenSquared();

	if (local24[1] < local24[0]) {
		local1c = 1;
	}

	if (local24[local1c] < 225.0f) {
		m_unk0x38 = 8;

		if (m_grec != NULL) {
			delete m_grec;
			m_grec = NULL;
		}

		if (m_pInfo != NULL) {
			m_pInfo = NULL;
		}

		assert(m_boundary && m_destEdge && m_roi);

		LegoPathBoundary* boundaries[2];
		LegoOrientedEdge* maxE = NULL;
		boundaries[0] = m_boundary;

		if (m_destEdge->FUN_10048c40(local38)) {
			boundaries[1] = (LegoPathBoundary*) m_destEdge->OtherFace(m_boundary);
		}
		else {
			boundaries[1] = NULL;
		}

		float local78, local98;
		for (MxS32 i = 0; i < (MxS32) sizeOfArray(boundaries); i++) {
			if (boundaries[i] != NULL) {
				for (MxS32 j = 0; j < boundaries[i]->GetNumEdges(); j++) {
					LegoOrientedEdge* e = boundaries[i]->GetEdges()[j];

					if (e->GetMask0x03()) {
						Mx3DPointFloat local94(*e->GetPointA());
						local94 += *e->GetPointB();
						local94 /= 2.0f;

						local18 = local94;
						local18 -= local64[local1c];
						local98 = local18.LenSquared();

						local94 -= local38;
						local18 = local64[local1c];
						local18 -= local38;

						if (maxE == NULL || (local18.Dot(local94, local18) < 0.0f && local78 < local98)) {
							maxE = e;
							m_boundary = boundaries[i];
							local78 = local98;
						}
					}
				}
			}
		}

		assert(maxE);
		m_destEdge = maxE;

		if (m_boundary != boundaries[0]) {
			m_unk0xe4 = 1.0 - m_unk0xe4;
		}

		VTable0x9c();
	}

	return -1;
}

// FUNCTION: LEGO1 0x10042990
// FUNCTION: BETA10 0x1001b6e2
void Act3Brickster::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoOrientedEdge*& p_edge, float& p_unk0xe4)
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
	m_nextPizza = NULL;
}

// FUNCTION: LEGO1 0x10042ce0
MxResult Act3Shark::EatPizza(Act3Ammo* p_ammo)
{
	p_ammo->SetSharkFood(TRUE);
	m_eatPizzas.push_back(p_ammo);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10042d40
void Act3Shark::Animate(float p_time)
{
	LegoROI** roiMap = m_unk0x34->GetROIMap();

	if (m_nextPizza == NULL) {
		if (m_eatPizzas.size() > 0) {
			m_nextPizza = m_eatPizzas.front();
			m_eatPizzas.pop_front();
			m_unk0x2c = p_time;
			roiMap[1] = m_nextPizza->GetROI();
			m_unk0x3c = roiMap[1]->GetLocal2World()[3];
			roiMap[1]->SetVisibility(TRUE);
			roiMap[2]->SetVisibility(TRUE);
		}

		if (m_nextPizza == NULL) {
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
		LegoROI::ApplyAnimationTransformation(node, mat, duration, m_unk0x34->GetROIMap());
	}
	else {
		roiMap[1] = m_unk0x38;
		((Act3*) m_world)->RemovePizza(*m_nextPizza);
		m_nextPizza = NULL;
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
