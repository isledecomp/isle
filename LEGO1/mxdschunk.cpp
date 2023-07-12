#include "mxdschunk.h"

// OFFSET: LEGO1 0x100be050
MxDSChunk::MxDSChunk()
{
  this->m_length = 0;
  this->m_pStuff = NULL;
  this->m_buffer = -1;
  this->m_long1FromHeader = 0;
  this->m_long2FromHeader = 0;
}

// OFFSET: LEGO1 0x100be170
MxDSChunk::~MxDSChunk()
{
  if ((this->m_length & 1) != 0) {
    delete this->m_pStuff;
  }
}
