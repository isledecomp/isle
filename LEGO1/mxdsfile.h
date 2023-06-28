#ifndef MXDSFILE_H
#define MXDSFILE_H

#include "mxdssource.h"

class MxDSFile : public MxDSSource
{
public:
  __declspec(dllexport) MxDSFile(const char *filename, unsigned long skipReadingChunks);
  __declspec(dllexport) virtual ~MxDSFile(); // vtable+0x0
  __declspec(dllexport) virtual long Open(unsigned long); // vtable+0x14
  __declspec(dllexport) virtual long Close(); // vtable+0x18
  __declspec(dllexport) virtual long Read(unsigned char *,unsigned long); // vtable+0x20
  __declspec(dllexport) virtual long Seek(long,int); // vtable+0x24
  __declspec(dllexport) virtual unsigned long GetBufferSize(); // vtable+0x28
  __declspec(dllexport) virtual unsigned long GetStreamBuffersNum();  // vtable+0x2c
private:
  long ReadChunks();
  struct ChunkHeader {
    ChunkHeader()
      : majorVersion(0)
      , minorVersion(0)
      , bufferSize(0)
      , streamBuffersNum(0)
    {}

    unsigned short majorVersion;
    unsigned short minorVersion;
    unsigned long bufferSize;
    short streamBuffersNum;
    short reserved;
  };

  MxString m_filename;
  MXIOINFO m_io;
  ChunkHeader m_header;

  // If false, read chunks immediately on open, otherwise
  // skip reading chunks until ReadChunks is explicitly called.
  unsigned long m_skipReadingChunks;
};

#endif // MXDSFILE_H
