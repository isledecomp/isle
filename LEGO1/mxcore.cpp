#include "mxcore.h"

#include <string.h>

unsigned int g_mxcoreCount = 0;

MxCore::MxCore()
{
  m_id = g_mxcoreCount;
  g_mxcoreCount++;
}

MxCore::~MxCore()
{
}

long MxCore::Notify(MxParam &p)
{
  return 0;
}

long MxCore::Tickle()
{
  return 0;
}

const char *MxCore::GetClassName() const
{
  return "MxCore";
}

MxBool MxCore::IsClass(const char *name) const
{
  return strcmp(name, "MxCore") == 0;
}
