
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
MxResult LegoFileStream::Read(char* buffer, MxU32 size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fread(buffer, 1, size, m_hFile) == size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099300
MxResult LegoFileStream::Write(char* buffer, MxU32 size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fwrite(buffer, 1, size, m_hFile) == size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099340
MxResult LegoFileStream::Tell(MxU32* offset)
{
  if (m_hFile == NULL)
    return FAILURE;

  int got = ftell(m_hFile);
  if (got == -1)
    return FAILURE;

  *offset = got;
  return SUCCESS;
}

// OFFSET: LEGO1 0x10099370
MxResult LegoFileStream::Seek(MxU32 offset)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fseek(m_hFile, offset, 0) == 0) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x100993a0
MxResult LegoFileStream::Open(const char* filename, OpenFlags mode)
{
  char modeString[4];

  if (m_hFile != NULL)
    fclose(m_hFile);
  
  modeString[0] = '\0';
  if (mode & ReadBit)
  {
    m_mode = LEGOSTREAM_MODE_READ;
    strcat(modeString, "r");
  }

  if (mode & WriteBit)
  {
    if (m_mode != LEGOSTREAM_MODE_READ)
      m_mode = LEGOSTREAM_MODE_WRITE;
    strcat(modeString, "w");
  }

  if ((mode & 4) != 0)
    strcat(modeString, "b");
  else
    strcat(modeString, "t");

  return (m_hFile = fopen(filename, modeString)) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099080
LegoMemoryStream::LegoMemoryStream(char* buffer)
  : LegoStream()
{
  m_buffer = buffer;
  m_offset = 0;
}

// OFFSET: LEGO1 0x10099160
MxResult LegoMemoryStream::Read(char* buffer, MxU32 size)
{
  memcpy(buffer, m_buffer + m_offset, size);
  m_offset += size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x10099190
MxResult LegoMemoryStream::Write(char* buffer, MxU32 size)
{
  memcpy(m_buffer + m_offset, buffer, size);
  m_offset += size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994a0
MxResult LegoMemoryStream::Tell(MxU32* offset)
{
  *offset = m_offset;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994b0
MxResult LegoMemoryStream::Seek(MxU32 offset)
{
  m_offset = offset;
  return SUCCESS;
}


