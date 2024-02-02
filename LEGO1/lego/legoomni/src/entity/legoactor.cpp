#include "legoactor.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// FUNCTION: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk0x68 = 0.0f;
	m_unk0x6c = 0;
	m_unk0x70 = 0.0f;
	m_unk0x10 = 0;
	m_unk0x74 = 0;
}

// STUB: LEGO1 0x1002d320
LegoActor::~LegoActor()
{
	// TODO
}

// STUB: LEGO1 0x1002d390
void LegoActor::ParseAction(char*)
{
	// TODO
}

// STUB: LEGO1 0x1002d670
void LegoActor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	// TODO
}
