#include "policestate.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	m_unk0x0c = 0;
	m_unk0x08 = (rand() % 2 == 0) ? 501 : 500;
}

// FUNCTION: LEGO1 0x1005e990
MxResult PoliceState::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(ClassName());
	}

	if (p_legoFile->IsReadMode()) {
		p_legoFile->Read(&m_unk0x08, sizeof(m_unk0x08));
	}
	else {
		undefined4 unk0x08 = m_unk0x08;
		p_legoFile->Write(&unk0x08, sizeof(m_unk0x08));
	}

	return SUCCESS;
}
