#include "animstate.h"

DECOMP_SIZE_ASSERT(AnimState, 0x1c)
DECOMP_SIZE_ASSERT(ModelInfo, 0x30)
DECOMP_SIZE_ASSERT(AnimInfo, 0x30)

// FUNCTION: LEGO1 0x10064ff0
AnimState::AnimState()
{
	m_unk0x0c = 0;
	m_unk0x10 = NULL;
	m_unk0x14 = 0;
	m_unk0x18 = NULL;
}

// STUB: LEGO1 0x10065150
AnimState::~AnimState()
{
	// TODO
}

// STUB: LEGO1 0x100651d0
void AnimState::FUN_100651d0(MxU32, AnimInfo*, MxU32&)
{
	// TODO
}

// STUB: LEGO1 0x10065240
void AnimState::FUN_10065240(MxU32, AnimInfo*, MxU32)
{
	// TODO
}

// STUB: LEGO1 0x100652d0
MxResult AnimState::VTable0x1c(LegoFile* p_legoFile)
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100654f0
MxBool AnimState::SetFlag()
{
	// TODO
	return FALSE;
}
