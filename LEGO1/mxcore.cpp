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

// FIXME: based on another call, this might be an integer (100edf3c), or whatever undefined4 is
long MxCore::NotificationManager()
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
