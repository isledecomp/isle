#ifndef MXDSFILE_H
#define MXDSFILE_H

#include "mxdssource.h"

class MxDSFile : public MxDSSource
{
public:
  __declspec(dllexport) MxDSFile(const char *,unsigned long);
  __declspec(dllexport) virtual ~MxDSFile(); // vtable+0x0
  __declspec(dllexport) virtual long Open(unsigned long); // vtable+0x14
  __declspec(dllexport) virtual long Close(); // vtable+0x18
  __declspec(dllexport) virtual long Read(unsigned char *,unsigned long); // vtable+0x20
  __declspec(dllexport) virtual long Seek(long,int); // vtable+0x24
  __declspec(dllexport) virtual unsigned long GetBufferSize(); // vtable+0x28
  __declspec(dllexport) virtual unsigned long GetStreamBuffersNum();  // vtable+0x2c
private:
  char m_unknown[0x70];
  unsigned long m_buffersize;
};

#endif // MXDSFILE_H
