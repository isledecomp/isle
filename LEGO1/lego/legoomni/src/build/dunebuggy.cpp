#include "dunebuggy.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(DuneBuggy, 0x16c);

// FUNCTION: LEGO1 0x10067bb0
DuneBuggy::DuneBuggy()
{
	this->m_unk0x13c = 25.0;
	this->m_unk0x164 = 1.0;
}

// STUB: LEGO1 0x10067e30
MxResult DuneBuggy::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10067ec0
void DuneBuggy::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10067fa0
void DuneBuggy::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x10068060
MxU32 DuneBuggy::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100681b0
MxU32 DuneBuggy::VTable0xd4(MxType17NotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10068270
MxU32 DuneBuggy::VTable0xdc(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}
