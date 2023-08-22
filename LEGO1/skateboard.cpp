#include "skateboard.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168);

// OFFSET: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
  this->m_unk160 = 0;
  this->m_unk13c = 15.0;
  this->m_unk150 = 3.5;
  this->m_unk148 = 1;

  NotificationManager()->Register(this);
}
