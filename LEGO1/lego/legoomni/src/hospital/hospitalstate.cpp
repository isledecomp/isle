#include "hospitalstate.h"

DECOMP_SIZE_ASSERT(HospitalState, 0x18)

// FUNCTION: LEGO1 0x10076370
HospitalState::HospitalState()
{
	this->m_unk0xc = 0;
	this->m_unk0xe = 0;
	this->m_unk0x10 = 0;
	this->m_unk0x12 = 0;
	this->m_unk0x14 = 0;
	this->m_unk0x16 = 0;
}

// STUB: LEGO1 0x10076530
MxResult HospitalState::VTable0x1c(LegoFileStream* p_legoFileStream)
{
	// TODO
	return 0;
}
