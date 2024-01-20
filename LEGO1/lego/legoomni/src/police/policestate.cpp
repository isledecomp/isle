#include "policestate.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	m_unk0xc = 0;
	m_unk0x8 = (rand() % 2 == 0) ? 501 : 500;
}

// FUNCTION: LEGO1 0x1005e990
MxResult PoliceState::VTable0x1c(LegoFileStream* p_legoFileStream)
{
	if (p_legoFileStream->IsWriteMode()) {
		p_legoFileStream->FUN_10006030(this->ClassName());
	}
	if (p_legoFileStream->IsReadMode()) {
		p_legoFileStream->Write(&m_unk0x8, sizeof(MxU32));
	}
	else if (p_legoFileStream->IsWriteMode()) {
		p_legoFileStream->Read(&m_unk0x8, sizeof(MxU32));
	}
	return SUCCESS;
}
