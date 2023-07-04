
#include "mxfile.h"

#include <cstdio>
#include <string>

// OFFSET: LEGO1 0x10045ae0
MxBool MxFile::IsWriteMode()
{
  return m_mode == MXFILE_MODE_WRITE;
}

// OFFSET: LEGO1 0x10045af0
MxBool MxFile::IsReadMode()
{
  return m_mode == MXFILE_MODE_READ;
}

// OFFSET: LEGO1 0x100991c0
MxSystemFile::MxSystemFile()
  : MxFile()
{
  m_hFile = NULL;
}

// OFFSET: LEGO1 0x10099250
MxSystemFile::~MxSystemFile()
{
  if (m_hFile != NULL)
    fclose(m_hFile);
}

// OFFSET: LEGO1 0x100992c0
MxResult MxSystemFile::Read(char* buffer, MxU32 size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fread(buffer, 1, size, m_hFile) == size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099300
MxResult MxSystemFile::Write(char* buffer, MxU32 size)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fwrite(buffer, 1, size, m_hFile) == size) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099340
MxResult MxSystemFile::Tell(MxU32* offset)
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
MxResult MxSystemFile::Seek(MxU32 offset)
{
  if (m_hFile == NULL)
    return FAILURE;

  return (fseek(m_hFile, offset, 0) == 0) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x100993a0
MxResult MxSystemFile::Open(const char* filename, OpenFlags mode)
{
  char modeString[4];

  if (m_hFile != NULL)
    fclose(m_hFile);
  
  modeString[0] = '\0';
  if (mode & ReadBit)
  {
    m_mode = MXFILE_MODE_READ;
    strcat(modeString, "r");
  }

  if (mode & WriteBit)
  {
    if (m_mode != MXFILE_MODE_READ)
      m_mode = MXFILE_MODE_WRITE;
    strcat(modeString, "w");
  }

  if ((mode & 4) != 0)
    strcat(modeString, "b");
  else
    strcat(modeString, "t");

  return (m_hFile = fopen(filename, modeString)) ? SUCCESS : FAILURE;
}

// OFFSET: LEGO1 0x10099080
MxMemoryFile::MxMemoryFile(char* buffer)
  : MxFile()
{
  m_buffer = buffer;
  m_offset = 0;
}

// OFFSET: LEGO1 0x10099160
MxResult MxMemoryFile::Read(char* buffer, MxU32 size)
{
  memcpy(buffer, m_buffer + m_offset, size);
  m_offset += size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x10099190
MxResult MxMemoryFile::Write(char* buffer, MxU32 size)
{
  memcpy(m_buffer + m_offset, buffer, size);
  m_offset += size;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994a0
MxResult MxMemoryFile::Tell(MxU32* offset)
{
  *offset = m_offset;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100994b0
MxResult MxMemoryFile::Seek(MxU32 offset)
{
  m_offset = offset;
  return SUCCESS;
}


