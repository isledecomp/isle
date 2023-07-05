
#include "legostream.h"

#include <cstdio>
#include <string>

// OFFSET: LEGO1 0x10045ae0
MxBool LegoStream::IsWriteMode()
{
  return m_mode == LEGOSTREAM_MODE_WRITE;
}

// OFFSET: LEGO1 0x10045af0
MxBool LegoStream::IsReadMode()
{
  return m_mode == LEGOSTREAM_MODE_READ;
}

// OFFSET: LEGO1 0x100991c0
LegoFileStream::LegoFileStream()
  : LegoStream()
{
  m_hFile = NULL;
}

// OFFSET: LEGO1 0x10099250
LegoFileStream::~LegoFileStream()
{
  if (m_hFile != NULL)
    fclose(m_hFile);
}

// OFFSET: LEGO1 0x100992c0
MxResult LegoFileStream::Read(char* p_buffer, MxU32 p_size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fread(p_buffer, 1, p_size, m_hFile) == p_size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099300
MxResult LegoFileStream::Write(char* p_buffer, MxU32 p_size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fwrite(p_buffer, 1, p_size, m_hFile) == p_size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099340
MxResult LegoFileStream::Tell(MxU32* p_offset)
{
  if (m_hFile == NULL)
    return FAILURE;

  int got = ftell(m_hFile);
  if (got == -1)
    return FAILURE;

  *p_offset = got;
  return SUCCESS;
}

// OFFSET: LEGO1 0x10099370
MxResult LegoFileStream::Seek(MxU32 p_offset)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fseek(m_hFile, p_offset, 0) == 0) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x100993a0
MxResult LegoFileStream::Open(const char* p_filename, OpenFlags p_mode)
{
  char modeString[4];

  if (m_hFile != NULL)
    fclose(m_hFile);
  
  modeString[0] = '\0';
  if (p_mode & ReadBit)
  {
    m_mode = LEGOSTREAM_MODE_READ;
    strcat(modeString, "r");
  }

  if (p_mode & WriteBit)
  {
    if (m_mode != LEGOSTREAM_MODE_READ)
      m_mode = LEGOSTREAM_MODE_WRITE;
    strcat(modeString, "w");
  }

  if ((p_mode & 4) != 0)
    strcat(modeString, "b");
  else
    strcat(modeString, "t");

  return (m_hFile = fopen(p_filename, modeString)) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099080
LegoMemoryStream::LegoMemoryStream(char* p_buffer)
  : LegoStream()
{
  m_buffer = p_buffer;
  m_offset = 0;
}

// OFFSET: LEGO1 0x10099160
MxResult LegoMemoryStream::Read(char* p_buffer, MxU32 p_size)
{
  memcpy(p_buffer, m_buffer + m_offset, p_size);
  m_offset += p_size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x10099190
MxResult LegoMemoryStream::Write(char* p_buffer, MxU32 p_size)
{
  memcpy(m_buffer + m_offset, p_buffer, p_size);
  m_offset += p_size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994a0
MxResult LegoMemoryStream::Tell(MxU32* p_offset)
{
  *p_offset = m_offset;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994b0
MxResult LegoMemoryStream::Seek(MxU32 p_offset)
{
  m_offset = p_offset;
  return SUCCESS;
}


