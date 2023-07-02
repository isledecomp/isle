#include "mxcore.h"

// 0x1010141c
unsigned int g_mxcoreCount = 0;

// OFFSET: LEGO1 0x100ae1a0
MxCore::MxCore()
{
  m_id = g_mxcoreCount;
  g_mxcoreCount++;
}

// OFFSET: LEGO1 0x100ae1e0
MxCore::~MxCore()
{
}

// OFFSET: LEGO1 0x100ae1f0
MxLong MxCore::Notify(MxParam &p)
{
  return 0;
}

// OFFSET: LEGO1 0x10001f70
MxLong MxCore::Tickle()
{
  return 0;
}