#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

class MxString : public MxCore
{
public:
  __declspec(dllexport) MxString(const MxString &);
  __declspec(dllexport) virtual ~MxString();
  __declspec(dllexport) const MxString &operator=(const char *);

  MxString();
  MxString(const char *);
  void ToUpperCase();
  void ToLowerCase();
  const MxString &operator=(MxString *);

  inline const char *GetData() const { return m_data; }

private:
  char *m_data;
  unsigned short m_length;

};

#endif // MXSTRING_H
