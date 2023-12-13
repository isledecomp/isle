#include "motorcycle.h"

DECOMP_SIZE_ASSERT(Motorcycle, 0x16c);

// FUNCTION: LEGO1 0x100357b0
Motorcycle::Motorcycle()
{
	this->m_unk0x13c = 40.0;
	this->m_unk0x150 = 1.75;
	this->m_unk0x148 = 1;
	this->m_unk0x164 = 1.0;
}
