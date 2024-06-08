#include "mxomnicreateflags.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxOmniCreateFlags, 0x02)

// FUNCTION: LEGO1 0x100b0a30
// FUNCTION: BETA10 0x10130a1c
MxOmniCreateFlags::MxOmniCreateFlags()
{
	m_flags1.m_bit0 = TRUE; // CreateObjectFactory
	m_flags1.m_bit1 = TRUE; // CreateVariableTable
	m_flags1.m_bit2 = TRUE; // CreateTickleManager
	m_flags1.m_bit3 = TRUE; // CreateNotificationManager
	m_flags1.m_bit4 = TRUE; // CreateVideoManager
	m_flags1.m_bit5 = TRUE; // CreateSoundManager
	m_flags1.m_bit6 = TRUE; // CreateMusicManager
	m_flags1.m_bit7 = TRUE; // CreateEventManager

	m_flags2.m_bit1 = TRUE; // CreateTimer
	m_flags2.m_bit2 = TRUE; // CreateStreamer
}
