#ifndef MXIOINFO_H
#define MXIOINFO_H

#include <windows.h>

#include "mmsystem.h"

class MXIOINFO
{
public:
  MXIOINFO();
  __declspec(dllexport) ~MXIOINFO();

  unsigned short Open(const char *filename, DWORD fdwOpen);
  unsigned short Close(long arg);
  LONG Seek(LONG lOffset, int iOrigin);
  unsigned long Read(HPSTR pch, LONG cch);
  unsigned short SetBuffer(LPSTR pchBuffer, LONG cchBuffer, UINT fuBuffer);
  unsigned short Descend(LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend);
  unsigned short Flush(int arg);
  unsigned short Something(UINT flags);

  inline LONG GetCurrentOffset() { return _llseek((HFILE)m_info.hmmio, 0, SEEK_CUR); }

  MMIOINFO m_info;
};

#endif // MXIOINFO_H
