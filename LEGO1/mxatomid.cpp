#include "mxatomid.h"

#include <map>

// OFFSET: LEGO1 0x100acf90 STUB
MxAtomId::MxAtomId(const char *p_text, LookupMode p_mode)
{
  // Fake temporary implementation, real one is hard to work out a decomp for.
  static char* s_entries[256]; // 256 is enough for anyone
  static int s_entryCount = 0;
  for (int i = 0; i < s_entryCount; ++i)
  {
    if (!strcmp(s_entries[i], p_text))
    {
      m_internal = s_entries[i];
      return;
    }
  }
  m_internal = new char[strlen(p_text) + 1];
  strcpy(m_internal, p_text);
  s_entries[s_entryCount++] = m_internal;
  if (s_entryCount == 100)
  {
    printf("Debug|Too many atom entries!\n");
    exit(0);
  }

  // TODO: Real decomp implementation
}

// OFFSET: LEGO1 0x100acfd0
MxAtomId::~MxAtomId()
{
  // TODO
}

// OFFSET: LEGO1 0x100ad1c0 STUB
MxAtomId &MxAtomId::operator=(const MxAtomId &id)
{
  // Fake temporary implementation
  m_internal = id.m_internal;
  return *this;

  // TODO: Real decomp implementation
}
