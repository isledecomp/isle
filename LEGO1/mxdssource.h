#ifndef MXDSSOURCE_H
#define MXDSSOURCE_H

#include "mxcore.h"

class MxDSSource : public MxCore
{
public:
  MxDSSource()
    : m_lengthInDWords(0)
    , m_pBuffer(0)
    , m_position(-1)
  {}

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