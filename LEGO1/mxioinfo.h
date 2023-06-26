#ifndef MXIOINFO_H
#define MXIOINFO_H

#include "windows.h"
#include "mmsystem.h"
class MXIOINFO
{
public:
  MXIOINFO();
  __declspec(dllexport) ~MXIOINFO();

  unsigned short Open(const char *filename, DWORD fdwOpen);
  void Close(long arg);
  LONG Seek(LONG lOffset, int iOrigin);
  unsigned long Read(HPSTR pch, LONG cch);
  void SetBuffer(LPSTR pchBuffer, LONG cchBuffer);
  unsigned short Descend(LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend);

  MMIOINFO m_info;
};

#endif // MXIOINFO_H
