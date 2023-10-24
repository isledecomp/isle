#include "ambulance.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(Ambulance, 0x184);

// OFFSET: LEGO1 0x10035ee0
Ambulance::Ambulance()
{
	this->m_unk168 = 0;
	this->m_unk16a = -1;
	this->m_unk164 = 0;
	this->m_unk16c = 0;
	this->m_unk174 = -1;
	this->m_unk16e = 0;
	this->m_unk178 = -1;
	this->m_unk170 = 0;
	this->m_unk172 = 0;
	this->m_unk13c = 40.0;
	this->m_unk17c = 1.0;
}