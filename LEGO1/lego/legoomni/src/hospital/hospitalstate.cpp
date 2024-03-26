#include "hospitalstate.h"

DECOMP_SIZE_ASSERT(HospitalState, 0x18)

// FUNCTION: LEGO1 0x10076370
HospitalState::HospitalState()
{
	m_unk0x0c = 0;
	m_unk0x0e = 0;
	m_unk0x10 = 0;
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x16 = 0;
}

// FUNCTION: LEGO1 0x10076530
MxResult HospitalState::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(ClassName());
	}

	if (p_legoFile->IsWriteMode()) {
		// A write variable needs to be used here, otherwise
		// the compiler aggresively optimizes the function
		MxS16 write;

		write = m_unk0x0c;
		p_legoFile->Write(&write, sizeof(m_unk0x0c));
		write = m_unk0x0e;
		p_legoFile->Write(&write, sizeof(m_unk0x0e));
		write = m_unk0x10;
		p_legoFile->Write(&write, sizeof(m_unk0x10));
		write = m_unk0x12;
		p_legoFile->Write(&write, sizeof(m_unk0x12));
		write = m_unk0x14;
		p_legoFile->Write(&write, sizeof(m_unk0x14));
		write = m_unk0x16;
		p_legoFile->Write(&write, sizeof(m_unk0x16));
	}
	else if (p_legoFile->IsReadMode()) {
		p_legoFile->Read(&m_unk0x0c, sizeof(m_unk0x0c));
		p_legoFile->Read(&m_unk0x0e, sizeof(m_unk0x0e));
		p_legoFile->Read(&m_unk0x10, sizeof(m_unk0x10));
		p_legoFile->Read(&m_unk0x12, sizeof(m_unk0x12));
		p_legoFile->Read(&m_unk0x14, sizeof(m_unk0x14));
		p_legoFile->Read(&m_unk0x16, sizeof(m_unk0x16));
	}

	return SUCCESS;
}
