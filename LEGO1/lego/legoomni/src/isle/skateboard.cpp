#include "skateboard.h"

#include "decomp.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168);

// FUNCTION: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
	this->m_unk0x160 = 0;
	this->m_unk0x13c = 15.0;
	this->m_unk0x150 = 3.5;
	this->m_unk0x148 = 1;

	NotificationManager()->Register(this);
}
