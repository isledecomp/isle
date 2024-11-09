#include "doors.h"

#include "legopathboundary.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "roi/legoroi.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(Doors, 0x1f8)

// FUNCTION: LEGO1 0x10066100
// FUNCTION: BETA10 0x10026850
MxResult Doors::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	assert(m_ltDoor && m_rtDoor);

	if (m_unk0x154 == 1) {
		m_unk0x154 = 2;
		m_unk0x158 = Timer()->GetTime();
		m_ltDoorLocal = m_ltDoor->GetLocal2World();
		m_rtDoorLocal = m_rtDoor->GetLocal2World();
	}

	return m_unk0x1f4 < 0.001 ? SUCCESS : FAILURE;
}

// STUB: LEGO1 0x10066190
// FUNCTION: BETA10 0x1002696b
double Doors::VTable0xcc(float p_float)
{
	return 0.0;
}

// FUNCTION: LEGO1 0x10066250
// FUNCTION: BETA10 0x10026a45
void Doors::VTable0x70(float p_float)
{
	assert(m_ltDoor && m_rtDoor);

	// TODO: Match
	m_roi->SetVisibility(m_boundary->GetFlag0x10());

	switch (m_unk0x154) {
	case 0:
		m_unk0x154 = 1;
		m_state = 0;
		break;
	case 1:
		break;
	case 2:
		float local8 = VTable0xcc(p_float);

		if (local8 > 0.0f) {
			MxMatrix local58(m_ltDoorLocal);
			Vector3 local10(local58[3]);

			local10.Clear();
			local58.RotateY(-local8);
			local10 = m_ltDoorLocal[3];
			m_ltDoor->FUN_100a58f0(local58);
			m_ltDoor->VTable0x14();

			local58 = m_rtDoorLocal;
			local10.Clear();
			local58.RotateY(local8);
			local10 = m_rtDoorLocal[3];
			m_rtDoor->FUN_100a58f0(local58);
			m_rtDoor->VTable0x14();

			m_unk0x1f4 = local8;
		}

		if (m_unk0x158 + 6000.0f < p_float) {
			m_ltDoor->FUN_100a58f0(m_ltDoorLocal);
			m_rtDoor->FUN_100a58f0(m_rtDoorLocal);
			m_ltDoor->VTable0x14();
			m_rtDoor->VTable0x14();
			m_unk0x154 = 1;
			m_state = 0;
			m_unk0x1f4 = 0;
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
	assert(!strncmp(m_roi->GetName(), "rcdor", 5));

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
