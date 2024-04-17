#include "mxomnicreateflags.h"

// FUNCTION: LEGO1 0x100b0a30
// FUNCTION: BETA10 0x10130a1c
MxOmniCreateFlags::MxOmniCreateFlags()
{
	this->m_flags1.m_bit0 = TRUE; // CreateObjectFactory
	this->m_flags1.m_bit1 = TRUE; // CreateVariableTable
	this->m_flags1.m_bit2 = TRUE; // CreateTickleManager
	this->m_flags1.m_bit3 = TRUE; // CreateNotificationManager
	this->m_flags1.m_bit4 = TRUE; // CreateVideoManager
	this->m_flags1.m_bit5 = TRUE; // CreateSoundManager
	this->m_flags1.m_bit6 = TRUE; // CreateMusicManager
	this->m_flags1.m_bit7 = TRUE; // CreateEventManager

	this->m_flags2.m_bit1 = TRUE; // CreateTimer
	this->m_flags2.m_bit2 = TRUE; // CreateStreamer
}
