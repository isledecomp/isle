#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

class MxString : public MxCore
{
public:
  __declspec(dllexport) virtual ~MxString();

private:
  char *m_data;
  unsigned short m_length;

};

#endif // MXSTRING_H
