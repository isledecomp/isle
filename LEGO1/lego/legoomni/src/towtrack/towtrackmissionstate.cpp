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
	m_unk0x1c = 0;
	m_color1 = 0;
	m_color2 = 0;
	m_color3 = 0;
	m_color4 = 0;
}

// FUNCTION: LEGO1 0x1004dde0
MxResult TowTrackMissionState::VTable0x1c(LegoFileStream* p_legoFileStream)
{
	if (p_legoFileStream->IsWriteMode()) {
		p_legoFileStream->FUN_10006030(this->ClassName());
	}

	if (p_legoFileStream->IsReadMode()) {
		p_legoFileStream->Read(&m_unk0x12, sizeof(MxU16));
		p_legoFileStream->Read(&m_unk0x14, sizeof(MxU16));
		p_legoFileStream->Read(&m_unk0x16, sizeof(MxU16));
		p_legoFileStream->Read(&m_unk0x18, sizeof(MxU16));
		p_legoFileStream->Read(&m_unk0x1a, sizeof(MxU16));
		p_legoFileStream->Read(&m_unk0x1c, sizeof(MxU16));
		p_legoFileStream->Read(&m_color1, sizeof(MxU16));
		p_legoFileStream->Read(&m_color2, sizeof(MxU16));
		p_legoFileStream->Read(&m_color3, sizeof(MxU16));
		p_legoFileStream->Read(&m_color4, sizeof(MxU16));
	}
	else if (p_legoFileStream->IsWriteMode()) {
		MxU16 write = m_unk0x12;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_unk0x14;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_unk0x16;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_unk0x18;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_unk0x1a;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_unk0x1c;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_color1;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_color2;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_color3;
		p_legoFileStream->Write(&write, sizeof(MxU16));

		write = m_color4;
		p_legoFileStream->Write(&write, sizeof(MxU16));
	}

	return SUCCESS;
}
