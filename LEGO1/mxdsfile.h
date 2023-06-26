#ifndef MXDSFILE_H
#define MXDSFILE_H

#include "mxcore.h"
#include "mxstring.h"
#include "mxioinfo.h"
#include "mxdssource.h"
class MxDSFile : public MxDSSource
{
public:
  __declspec(dllexport) MxDSFile(const char *filename, unsigned long skipReadingChunks);
  __declspec(dllexport) ~MxDSFile();
  __declspec(dllexport) long Open(unsigned long);
  __declspec(dllexport) long Close();
  __declspec(dllexport) long Read(unsigned char *,unsigned long);
  __declspec(dllexport) long Seek(long,int);
  __declspec(dllexport) unsigned long GetBufferSize();
  __declspec(dllexport) unsigned long GetStreamBuffersNum();

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
