#include "mxdsfile.h"

// OFFSET: LEGO1 0x100c0120
const char* MxDSFile::GetClassName() {
  return "MxDSFile";
}

unsigned long MxDSFile::GetBufferSize()
{
  return this->m_buffersize;
}

