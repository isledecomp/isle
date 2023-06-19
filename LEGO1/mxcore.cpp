#include "mxcore.h"

#include <string.h>

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
long MxCore::Notify(MxParam &p)
{
  return 0;
}

// OFFSET: LEGO1 0x10001f70
long MxCore::Tickle()
{
  return 0;
}

// OFFSET: LEGO1 0x100144c0
const char *MxCore::GetClassName() const
{
  return "MxCore";
}

// OFFSET: LEGO1 0x100140d0
MxBool MxCore::IsClass(const char *name) const
{
  return strcmp(name, "MxCore") == 0;
}
