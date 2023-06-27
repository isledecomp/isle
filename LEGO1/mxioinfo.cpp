#include "mxioinfo.h"

// OFFSET: LEGO1 0x100cc800
MXIOINFO::MXIOINFO()
{
  memset(&m_info, 0, sizeof(MMIOINFO));
}

// OFFSET: LEGO1 0x100cc820
MXIOINFO::~MXIOINFO()
{
  Close(0);
}

// OFFSET: LEGO1 0x100cc830
unsigned short MXIOINFO::Open(const char *filename, DWORD fdwOpen)
{
  return 0;
}

// OFFSET: LEGO1 0x100cc8e0
void MXIOINFO::Close(long arg)
{
  
}

// OFFSET: LEGO1 0x100cc930
unsigned long MXIOINFO::Read(HPSTR pch, LONG cch)
{
  return 0;
}

// OFFSET: LEGO1 0x100cca00
LONG MXIOINFO::Seek(LONG lOffset, int iOrigin)
{
  return 0;
}

// OFFSET: LEGO1 0x100ccbc0
void MXIOINFO::SetBuffer(LPSTR pchBuffer, LONG cchBuffer, LONG unk)
{
  
}

// OFFSET: LEGO1 0x100cce60
unsigned short MXIOINFO::Descend(LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend)
{
  return 0;
}