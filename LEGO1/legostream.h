#ifndef LEGOSTREAM_H
#define LEGOSTREAM_H

#include "decomp.h"
#include "mxtypes.h"

#include <iosfwd>

#define LEGOSTREAM_MODE_READ 1
#define LEGOSTREAM_MODE_WRITE 2

// VTABLE 0x100d7d80
class LegoStream
{
public:
  LegoStream() : m_mode(0) {}
  inline virtual ~LegoStream() {};

  virtual MxResult Read(char* p_buffer, MxU32 p_size) = 0;
  virtual MxResult Write(char* p_buffer, MxU32 p_size) = 0;
  virtual MxResult Tell(MxU32* p_offset) = 0;
  virtual MxResult Seek(MxU32 p_offset) = 0;

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

// VTABLE 0x100db730
class LegoFileStream : public LegoStream
{
public:
  LegoFileStream();
  virtual ~LegoFileStream();

  MxResult Read(char* p_buffer, MxU32 p_size) override;
  MxResult Write(char* p_buffer, MxU32 p_size) override;
  MxResult Tell(MxU32* p_offset) override;
  MxResult Seek(MxU32 p_offset) override;

  MxResult Open(const char* p_filename, OpenFlags p_mode);

private:
  FILE *m_hFile;
};

// VTABLE 0x100db710
class LegoMemoryStream : public LegoStream
{
public:
  LegoMemoryStream(char* p_buffer);
  ~LegoMemoryStream() {}

  MxResult Read(char* p_buffer, MxU32 p_size) override;
  MxResult Write(char* p_buffer, MxU32 p_size) override;
  MxResult Tell(MxU32* p_offset) override;
  MxResult Seek(MxU32 p_offset) override;

private:
  char *m_buffer;
  MxU32 m_offset;
};

#endif // LEGOSTREAM_H