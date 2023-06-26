#include "mxdsfile.h"

#include <stdio.h>

#define SI_MAJOR_VERSION 2
#define SI_MINOR_VERSION 2

#define FCC_OMNI 0x494e4d4f
#define FCC_MxHd 0x6448784d
#define FCC_MxOf 0x664f784d

// OFFSET: LEGO1 0x100cc4b0
MxDSFile::MxDSFile(const char *filename, unsigned long skipReadingChunks)
{
  m_filename = filename;
  m_skipReadingChunks = skipReadingChunks;
}

// OFFSET: LEGO1 0x100bfed0
MxDSFile::~MxDSFile()
{
  Close();
}

// OFFSET: LEGO1 0x100cc590
long MxDSFile::Open(unsigned long uStyle)
{
  // No idea what's stopping this one matching, but I'm pretty
  // confident it has the correct behavior.
  memset(&m_io, 0, sizeof(MXIOINFO));
  if (m_io.Open(m_filename.GetData(), uStyle) != 0) {
    return -1;
  }

  m_io.SetBuffer(NULL, 0);
  m_position = 0;

  long longResult = 1;
  if (m_skipReadingChunks == 0)
  {
    longResult = ReadChunks();
  }
  if (longResult != 0)
  {
    Close(); // vtable + 0x18
    return longResult;
  }
  Seek(0, 0); // vtable + 0x24
  return 0;
}

// OFFSET: LEGO1 0x100cc780
long MxDSFile::Read(unsigned char *pch, unsigned long cch)
{
  if (m_io.Read((char*)pch, cch) != cch)
    return -1;

  m_position += cch;
  return 0;
}

// OFFSET: LEGO1 0x100cc620
long MxDSFile::ReadChunks()
{
  _MMCKINFO topChunk;
  _MMCKINFO childChunk;
  char tempBuffer[80];
  
  topChunk.fccType = FCC_OMNI;
  if (m_io.Descend(&topChunk, NULL, MMIO_FINDRIFF) != 0) {
    return -1;
  }
  childChunk.ckid = FCC_MxHd;
  if (m_io.Descend(&childChunk, &topChunk, 0) != 0) {
    return -1;
  }

  m_io.Read((char*)&m_header, 0xc);
  if ((m_header.majorVersion == SI_MAJOR_VERSION) && (m_header.minorVersion == SI_MINOR_VERSION))
  {
    childChunk.ckid = FCC_MxOf;
    if (m_io.Descend(&childChunk, &topChunk, 0) != 0) {
      return -1;
    }
    unsigned long* pLengthInDWords = &m_lengthInDWords;
    m_io.Read((char *)pLengthInDWords, 4);
    m_pBuffer = malloc(*pLengthInDWords * 4);
    m_io.Read((char*)m_pBuffer, *pLengthInDWords * 4);
    return 0;
  }
  else
  {
    sprintf(tempBuffer, "Wrong SI file version. %d.%d expected.", SI_MAJOR_VERSION, SI_MINOR_VERSION);
    MessageBoxA(NULL, tempBuffer, NULL, MB_ICONERROR);
    return -1;
  }
}

// OFFSET: LEGO1 0x100cc7b0
long MxDSFile::Seek(long lOffset, int iOrigin)
{
  return (m_position = m_io.Seek(lOffset, iOrigin)) == 0xFFFFFFFF ? -1 : 0;
}

// OFFSET: LEGO1 0x100cc7e0
unsigned long MxDSFile::GetBufferSize()
{
  return m_header.bufferSize;
}

// OFFSET: LEGO1 0x100cc7f0
unsigned long MxDSFile::GetStreamBuffersNum()
{
  return m_header.streamBuffersNum;
}

// OFFSET: LEGO1 0x100cc740
long MxDSFile::Close()
{
  m_io.Close(0);
  m_position = -1;
  memset(&m_header, 0, sizeof(m_header));
  if (m_lengthInDWords != 0)
  {
    m_lengthInDWords = 0;
    free(m_pBuffer);
    m_pBuffer = NULL;
  }
  return 0;
}