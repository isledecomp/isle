#include "jukebox.h"

#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk100 = 0;
	m_unkfc = 0;
	NotificationManager()->Register(this);
}
