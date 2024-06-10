#include "legoraceactor.h"

DECOMP_SIZE_ASSERT(LegoRaceActor, 0x180)

// FUNCTION: LEGO1 0x100145d0
LegoRaceActor::LegoRaceActor()
{
	m_unk0x70 = 0;
	m_unk0x08 = 0;
}

// STUB: LEGO1 0x10014750
MxS32 LegoRaceActor::VTable0x68(Vector3&, Vector3&, Vector3&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100147f0
MxU32 LegoRaceActor::VTable0x90(float, Matrix4&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014a00
MxResult LegoRaceActor::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}
