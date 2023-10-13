#include "mxdssource.h"

// OFFSET: LEGO1 0x100bffd0
void MxDSSource::FUN_100bffd0(void* p_unk)
{
  // TODO: Calls read, reading into a buffer somewhere in p_unk.
  Read(NULL, 0);
}

// OFFSET: LEGO1 0x100bfff0
MxLong MxDSSource::GetLengthInDWords()
{
  return m_lengthInDWords;
}

// OFFSET: LEGO1 0x100c0000
MxU32 *MxDSSource::GetBuffer()
{
  return m_pBuffer;
}