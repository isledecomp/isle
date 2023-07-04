#ifndef MXIOINFO_H
#define MXIOINFO_H

#include <windows.h>
#include <mmsystem.h>

#include "mxtypes.h"

class MXIOINFO
{
public:
  MXIOINFO();
  __declspec(dllexport) ~MXIOINFO();

  MxU16 Open(const char *filename, DWORD fdwOpen);
  void Close(MxLong arg);
  LONG Seek(LONG lOffset, int iOrigin);
  MxULong Read(HPSTR pch, LONG cch);
  void SetBuffer(LPSTR pchBuffer, LONG cchBuffer, LONG unk);
  MxU16 Descend(LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend);

  MMIOINFO m_info;
};

#endif // MXIOINFO_H
