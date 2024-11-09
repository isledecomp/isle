#include "doors.h"

#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(Doors, 0x1f8)

// FUNCTION: LEGO1 0x10066100
MxResult Doors::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	if (m_unk0x154 == 1) {
		m_unk0x154 = 2;

		m_unk0x158 = Timer()->GetTime();

		m_unk0x164 = *m_unk0x15c;
		m_unk0x1ac = *m_unk0x160;
	}

	if (m_unk0x1f4 < 0.001) {
		return SUCCESS;
	}

	return FAILURE;
}

// STUB: LEGO1 0x10066250
void Doors::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x100664e0
void Doors::ParseAction(char*)
{
	// TODO
}
