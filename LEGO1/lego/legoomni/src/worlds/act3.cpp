#include "act3.h"

#include "legonavcontroller.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Act3, 0x4274)
DECOMP_SIZE_ASSERT(Act3State, 0x0c)
DECOMP_SIZE_ASSERT(Act3ListElement, 0x0c)
DECOMP_SIZE_ASSERT(Act3List, 0x10)

// FUNCTION: LEGO1 0x10072270
// FUNCTION: BETA10 0x10015470
Act3::Act3()
{
	m_unk0xf8 = 0;
	m_unk0x41fc = 0;
	m_unk0x4200 = 0;
	m_unk0x4204 = 0;
	m_unk0x4208 = 0;
	m_helicopter = NULL;
	m_unk0x4210 = 0;
	m_unk0x4214 = -1;
	m_unk0x421e = 0;

	memset(m_unk0x4230, 0, sizeof(m_unk0x4230));

	NavController()->ResetMaxLinearAccel(NavController()->GetMaxLinearAccel() * 30.0f);
	NavController()->ResetMaxLinearDeccel(NavController()->GetMaxLinearDeccel() * 30.0f);
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10072500
MxBool Act3::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x100726a0
Act3::~Act3()
{
	// TODO
}

// STUB: LEGO1 0x100727e0
MxBool Act3::FUN_100727e0(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10072980
MxBool Act3::FUN_10072980(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10072c30
MxResult Act3::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10072d50
void Act3::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// STUB: LEGO1 0x10072de0
MxLong Act3::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10073270
void Act3::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10073300
MxResult Act3::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10073400
void Act3::FUN_10073400()
{
}

// STUB: LEGO1 0x10073430
void Act3::FUN_10073430()
{
}

// STUB: LEGO1 0x10073a90
void Act3::Enable(MxBool p_enable)
{
	// TODO
}

// STUB: LEGO1 0x10073e40
void Act3::VTable0x60()
{
	// TODO
}

// STUB: LEGO1 0x10073e50
MxBool Act3::Escape()
{
	// TODO
	return FALSE;
}
