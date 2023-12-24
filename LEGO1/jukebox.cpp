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
