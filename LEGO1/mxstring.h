#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

// VTABLE 0x100dc110
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
  MxString&  operator=(MxString *);
  MxString   operator+(const char *);
  MxString& operator+=(const char *);

  inline const char *GetData() const { return m_data; }

private:
  char *m_data;
  MxU16 m_length;

};

#endif // MXSTRING_H
