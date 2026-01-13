#include "doors.h"

#include "legopathboundary.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "roi/legoroi.h"
#include "tgl/tglvector.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(Doors, 0x1f8)

// GLOBAL: LEGO1 0x100d8e7c
// GLOBAL: BETA10 0x101b954c
MxFloat g_timeMoving = 1000.0f;

// GLOBAL: LEGO1 0x100d8e80
// GLOBAL: BETA10 0x101b9550
MxFloat g_timeOpened = 4000.0f;

// GLOBAL: LEGO1 0x100d8e84
// GLOBAL: BETA10 0x101b9554
MxFloat g_totalTime = 6000.0f; // = g_timeMoving + g_totalTime + g_timeMoving

// FUNCTION: LEGO1 0x10066100
// FUNCTION: BETA10 0x10026850
MxResult Doors::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	assert(m_ltDoor && m_rtDoor);

	if (m_state == e_closed) {
		m_state = e_cycling;
		m_hitTime = Timer()->GetTime();
		m_ltDoorOriginalLocal = m_ltDoor->GetLocal2World();
		m_rtDoorOriginalLocal = m_rtDoor->GetLocal2World();
	}

	return m_angle < 0.001 ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10066190
// FUNCTION: BETA10 0x1002696b
MxFloat Doors::CalculateAngle(float p_time)
{
	MxFloat timeSinceHit;

	timeSinceHit = p_time - m_hitTime;

	if (timeSinceHit <= 0.0f) {
		return 0.0f;
	}

	if (timeSinceHit <= g_timeMoving) {
		return timeSinceHit * 1.570796 / g_timeMoving;
	}
	else if (timeSinceHit <= g_timeMoving + g_timeOpened) {
		return 1.570796012878418; // Pi / 2
	}
	else if (timeSinceHit <= g_totalTime) {
		return (1.0 - ((timeSinceHit - g_timeOpened) - g_timeMoving) / g_timeMoving) * 1.570796;
	}

	return 0.0f;
}

// FUNCTION: LEGO1 0x10066250
// FUNCTION: BETA10 0x10026a45
void Doors::Animate(float p_time)
{
	assert(m_ltDoor && m_rtDoor);

	// TODO: Match
	m_roi->SetVisibility(m_boundary->GetVisibility());

	switch (m_state) {
	case e_none:
		m_state = e_closed;
		m_actorState = c_initial;
		break;
	case e_closed:
		break;
	case e_cycling:
		float angle = CalculateAngle(p_time);

		if (angle > 0.0f) {
			MxMatrix transform(m_ltDoorOriginalLocal);
			Vector3 position(transform[3]);

			position.Clear();
			transform.RotateY(-angle);
			position = m_ltDoorOriginalLocal[3];
			m_ltDoor->SetLocal2World(transform);
			m_ltDoor->WrappedUpdateWorldData();

			transform = m_rtDoorOriginalLocal;
			position.Clear();
			transform.RotateY(angle);
			position = m_rtDoorOriginalLocal[3];
			m_rtDoor->SetLocal2World(transform);
			m_rtDoor->WrappedUpdateWorldData();

			m_angle = angle;
		}

		if (m_hitTime + g_totalTime < p_time) {
			m_ltDoor->SetLocal2World(m_ltDoorOriginalLocal);
			m_rtDoor->SetLocal2World(m_rtDoorOriginalLocal);
			m_ltDoor->WrappedUpdateWorldData();
			m_rtDoor->WrappedUpdateWorldData();
			m_state = e_closed;
			m_actorState = c_initial;
			m_angle = 0;
		}
	}
}

// FUNCTION: LEGO1 0x100664e0
// FUNCTION: BETA10 0x10026ceb
void Doors::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	assert(m_ltDoor == NULL && m_rtDoor == NULL);
	assert(m_roi);
	// clang-format off
	assert(!strncmp( m_roi->GetName(), "rcdor", 5 ));
	// clang-format on

	const CompoundObject* comp = m_roi->GetComp();

	for (CompoundObject::const_iterator it = comp->begin(); it != comp->end(); it++) {
		LegoROI* roi = (LegoROI*) *it;

		if (roi && (!strnicmp(roi->GetName(), "dor-lt", 6) || !strnicmp(roi->GetName(), "dor-sl", 6))) {
			m_ltDoor = roi;
		}
		else if (roi && (!strnicmp(roi->GetName(), "dor-rt", 6) || !strnicmp(roi->GetName(), "dor-sr", 6))) {
			m_rtDoor = roi;
		}
	}

	assert(m_ltDoor && m_rtDoor);
}
