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

  virtual MxLong Open(MxULong) = 0;
  virtual MxLong Close() = 0;
  virtual void SomethingWhichCallsRead(void* pUnknownObject);
  virtual MxResult Read(unsigned char *, MxULong) = 0;
  virtual MxLong Seek(MxLong, int) = 0;
  virtual MxULong GetBufferSize() = 0;
  virtual MxULong GetStreamBuffersNum() = 0;
  virtual MxLong GetLengthInDWords();
  virtual void* GetBuffer(); // 0x34

protected:
  MxULong m_lengthInDWords;
  void* m_pBuffer;
  MxLong m_position;
};

#endif // MXDSSOURCE_H
