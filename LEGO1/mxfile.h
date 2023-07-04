#ifndef MXFILE_H
#define MXFILE_H

#include "decomp.h"
#include "mxtypes.h"

#include <iosfwd>

#define MXFILE_MODE_READ 1
#define MXFILE_MODE_WRITE 2

class MxFile
{
public:
  MxFile() : m_mode(0) {}
  inline virtual ~MxFile() {};

  virtual MxResult Read(char* buffer, MxU32 size) = 0;
  virtual MxResult Write(char* buffer, MxU32 size) = 0;
  virtual MxResult Tell(MxU32* offset) = 0;
  virtual MxResult Seek(MxU32 offset) = 0;

  virtual MxBool IsWriteMode();
  virtual MxBool IsReadMode();

  enum OpenFlags
  {
    ReadBit = 1,
    WriteBit = 2,
    BinaryBit = 4,
  };

protected:
  MxU8 m_mode;
};

class MxSystemFile : public MxFile
{
public:
  MxSystemFile();
  virtual ~MxSystemFile();

  MxResult Read(char* buffer, MxU32 size) override;
  MxResult Write(char* buffer, MxU32 size) override;
  MxResult Tell(MxU32* offset) override;
  MxResult Seek(MxU32 offset) override;

  MxResult Open(const char* filename, OpenFlags mode);

private:
  FILE *m_hFile;
};

class MxMemoryFile : public MxFile
{
public:
  MxMemoryFile(char* buffer);
  ~MxMemoryFile() {}

  MxResult Read(char* buffer, MxU32 size) override;
  MxResult Write(char* buffer, MxU32 size) override;
  MxResult Tell(MxU32* offset) override;
  MxResult Seek(MxU32 offset) override;

private:
  char *m_buffer;
  MxU32 m_offset;
};

#endif // MXFILE_H