#include "towtrack.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180);

// FUNCTION: LEGO1 0x1004c720
TowTrack::TowTrack()
{
	this->m_unk0x168 = 0;
	this->m_unk0x16a = -1;
	this->m_unk0x164 = 0;
	this->m_unk0x16c = 0;
	this->m_unk0x170 = -1;
	this->m_unk0x16e = 0;
	this->m_unk0x174 = -1;
	this->m_unk0x13c = 40.0;
	this->m_unk0x178 = 1.0;
}
