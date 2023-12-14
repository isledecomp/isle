#include "isle.h"

#include "legoomni.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Isle, 0x140);

// FUNCTION: LEGO1 0x10030820
Isle::Isle()
{
	m_unk0xfc = 0;
	m_unk0x100 = 0;
	m_unk0x104 = 0;
	m_unk0x108 = 0;
	m_unk0x10c = 0;
	m_unk0x110 = 0;
	m_unk0x114 = 0;
	m_unk0x118 = 0;
	m_unk0x11c = 0;
	m_unk0x120 = 0;
	m_unk0x124 = 0;
	m_unk0x128 = 0;
	m_unk0xf8 = 0;
	m_unk0x13c = 0;

	NotificationManager()->Register(this);
}
