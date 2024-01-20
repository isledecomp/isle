#include "jukebox.h"

#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk0x100 = 0;
	m_unk0xfc = 0;
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x1005d6e0
MxBool JukeBox::VTable0x5c()
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x1005d8d0
MxResult JukeBox::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1005d980
MxLong JukeBox::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1005d9f0
void JukeBox::VTable0x50()
{
	// TODO
}

// STUB: LEGO1 0x1005dde0
void JukeBox::VTable0x68(MxBool p_add)
{
	// TODO
}

// STUB: LEGO1 0x1005de30
MxResult JukeBox::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1005de70
MxBool JukeBox::VTable0x64()
{
	// TODO
	return FALSE;
}
