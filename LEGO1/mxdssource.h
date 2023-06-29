#ifndef MXDSSOURCE_H
#define MXDSSOURCE_H

#include "mxcore.h"

// VTABLE 0x100dc8c8
class MxDSSource : public MxCore
{
public:
  MxDSSource()
    : m_lengthInDWords(0)
    , m_pBuffer(0)
    , m_position(-1)
  {}

  // OFFSET: LEGO1 0x100c0010
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10102588
    return "MxDSSource";
  }

  // OFFSET: LEGO1 0x100c0020
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSSource::ClassName()) || MxCore::IsA(name);
  }

  virtual long Open(unsigned long) = 0;
  virtual long Close() = 0;
  virtual void SomethingWhichCallsRead(void* pUnknownObject);
  virtual long Read(unsigned char *, unsigned long) = 0;
  virtual long Seek(long, int) = 0;
  virtual unsigned long GetBufferSize() = 0;
  virtual unsigned long GetStreamBuffersNum() = 0;
  virtual long GetLengthInDWords();

protected:
  unsigned long m_lengthInDWords;
  void* m_pBuffer;
  long m_position;
};

#endif // MXDSSOURCE_H
