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

  MxU16 Open(const char *, MxULong);
  MxU16 Close(MxLong);
  MxLong Read(void *, MxLong);
  MxLong Seek(MxLong, int);
  MxU16 SetBuffer(char *, MxLong, MxLong);
  MxU16 Flush(MxU16);
  MxU16 Advance(MxU16);
  MxU16 Descend(MMCKINFO *, const MMCKINFO *, MxU16);

  // The following is the MMIOINFO struct but with h_mmio set to type HFILE.

  /* general fields */
  DWORD           m_dwFlags;        /*  0 general status flags */
  FOURCC          m_fccIOProc;      /*  4 pointer to I/O procedure */
  LPMMIOPROC      m_pIOProc;        /*  8 pointer to I/O procedure */
  UINT            m_wErrorRet;      /*  c place for error to be returned */
  HTASK           m_htask;          /* 10 alternate local task */

  /* fields maintained by MMIO functions during buffered I/O */
  LONG            m_cchBuffer;      /* 14 size of I/O buffer (or 0L) */
  HPSTR           m_pchBuffer;      /* 18 start of I/O buffer (or NULL) */
  HPSTR           m_pchNext;        /* 1c pointer to next byte to read/write */
  HPSTR           m_pchEndRead;     /* 20 pointer to last valid byte to read */
  HPSTR           m_pchEndWrite;    /* 24 pointer to last byte to write */
  LONG            m_lBufOffset;     /* 28 disk offset of start of buffer */

  /* fields maintained by I/O procedure */
  LONG            m_lDiskOffset;    /* 2c disk offset of next read or write */
  DWORD           m_adwInfo[3];     /* 30 data specific to type of MMIOPROC */

  /* other fields maintained by MMIO */
  DWORD           m_dwReserved1;    /* 3c reserved for MMIO use */
  DWORD           m_dwReserved2;    /* 40 reserved for MMIO use */
  HFILE           m_hmmio;          /* 44 handle to open file */
};

#endif // MXIOINFO_H
