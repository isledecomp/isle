#include "towtrackmissionstate.h"

DECOMP_SIZE_ASSERT(TowTrackMissionState, 0x28)

// FUNCTION: LEGO1 0x1004dd30
TowTrackMissionState::TowTrackMissionState()
{
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x16 = 0;
	m_unk0x08 = 0;
	m_unk0x18 = 0;
	m_unk0x0c = 0;
	m_unk0x1a = 0;
	m_unk0x10 = 0;
	m_score1 = 0;
	m_score2 = 0;
	m_score3 = 0;
	m_score4 = 0;
	m_score5 = 0;
}

// FUNCTION: LEGO1 0x1004dde0
MxResult TowTrackMissionState::Serialize(LegoFile* p_legoFile)
{
	LegoState::Serialize(p_legoFile);

	if (p_legoFile->IsReadMode()) {
		p_legoFile->Read(&m_unk0x12, sizeof(m_unk0x12));
		p_legoFile->Read(&m_unk0x14, sizeof(m_unk0x14));
		p_legoFile->Read(&m_unk0x16, sizeof(m_unk0x16));
		p_legoFile->Read(&m_unk0x18, sizeof(m_unk0x18));
		p_legoFile->Read(&m_unk0x1a, sizeof(m_unk0x1a));
		p_legoFile->Read(&m_score1, sizeof(m_score1));
		p_legoFile->Read(&m_score2, sizeof(m_score2));
		p_legoFile->Read(&m_score3, sizeof(m_score3));
		p_legoFile->Read(&m_score4, sizeof(m_score4));
		p_legoFile->Read(&m_score5, sizeof(m_score5));
	}
	else if (p_legoFile->IsWriteMode()) {
		MxU16 write = m_unk0x12;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_unk0x14;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_unk0x16;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_unk0x18;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_unk0x1a;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_score1;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_score2;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_score3;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_score4;
		p_legoFile->Write(&write, sizeof(m_unk0x12));

		write = m_score5;
		p_legoFile->Write(&write, sizeof(m_unk0x12));
	}

	return SUCCESS;
}
