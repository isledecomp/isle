#include "mxdssource.h"

// OFFSET: LEGO1 0x100bffd0
void MxDSSource::SomethingWhichCallsRead(void* pUnknownObject)
{
  // TODO: Calls read, reading into a buffer somewhere in pUnknownObject.
  Read(NULL, 0);
}

// OFFSET: LEGO1 0x100bfff0
long MxDSSource::GetLengthInDWords()
{
  return m_lengthInDWords;
}