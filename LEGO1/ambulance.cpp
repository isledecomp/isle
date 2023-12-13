#include "ambulance.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(Ambulance, 0x184);

// FUNCTION: LEGO1 0x10035ee0
Ambulance::Ambulance()
{
	this->m_unk0x168 = 0;
	this->m_unk0x16a = -1;
	this->m_unk0x164 = 0;
	this->m_unk0x16c = 0;
	this->m_unk0x174 = -1;
	this->m_unk0x16e = 0;
	this->m_unk0x178 = -1;
	this->m_unk0x170 = 0;
	this->m_unk0x172 = 0;
	this->m_unk0x13c = 40.0;
	this->m_unk0x17c = 1.0;
}
