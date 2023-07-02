#include "mxioinfo.h"
#include "ddraw.h"

// OFFSET: LEGO1 0x100cc800
MXIOINFO::MXIOINFO()
{
  memset(&m_info, 0, sizeof(MMIOINFO));
}

// OFFSET: LEGO1 0x100cc820
MXIOINFO::~MXIOINFO()
{
  Close(0);
}

// OFFSET: LEGO1 0x100cc8e0
unsigned short MXIOINFO::Close(long arg)
{
  short result = 0;
  if (m_info.hmmio != NULL)
  {
    result = Flush(0);

    _lclose((HFILE)m_info.hmmio);
    m_info.hmmio = NULL;

    if (m_info.dwFlags & MMIO_ALLOCBUF)
      free(m_info.pchBuffer);

    m_info.pchEndWrite = NULL;
    m_info.pchEndRead = NULL;
    m_info.pchBuffer = NULL;
    m_info.dwFlags = 0;
  }
  return result;
}

// OFFSET: LEGO1 0x100cc830
unsigned short MXIOINFO::Open(const char *filename, DWORD fdwOpen)
{
  _OFSTRUCT lpReOpenBuff;
  unsigned short result = 0;

  m_info.lBufOffset = 0;
  m_info.lDiskOffset = 0;
  m_info.hmmio = (HMMIO)OpenFile(filename, &lpReOpenBuff, (unsigned short)fdwOpen);

  if (m_info.hmmio != (HMMIO)HFILE_ERROR)
  {
    m_info.dwFlags = fdwOpen;
    if (m_info.dwFlags & MMIO_ALLOCBUF)
    {
      long currentLength = m_info.cchBuffer != 0 ? m_info.cchBuffer : 0x2000;

      char* buffer = (char*)malloc(currentLength);
      if (buffer == NULL)
      {
        m_info.cchBuffer = 0;
        m_info.dwFlags &= ~MMIO_ALLOCBUF;
        m_info.pchBuffer = NULL;
        result = MMIOERR_OUTOFMEMORY;
      }
      else
      {
        m_info.cchBuffer = currentLength;
        m_info.pchBuffer = buffer;
      }
      m_info.pchEndRead = m_info.pchBuffer;
      m_info.pchNext = m_info.pchBuffer;
      m_info.pchEndWrite = m_info.pchBuffer + m_info.cchBuffer;
    }
  }
  else
  {
    result = MMIOERR_CANNOTOPEN;
  }
  return result;
}

// Not close to a match yet.
// OFFSET: LEGO1 0x100cc930
unsigned long MXIOINFO::Read(HPSTR pch, LONG cch)
{
  long result = 0;
  if (m_info.pchBuffer != NULL)
  {
    LONG toRead = m_info.pchEndRead - m_info.pchNext;
    unsigned long remaining = cch;
    do
    {
      if (toRead > 0) {
        if (toRead > remaining) {
          toRead = remaining;
        }
        remaining -= toRead;
        memcpy(pch, m_info.pchNext, toRead);
        m_info.pchNext += toRead;
      }
    } while (remaining && !Something(0) && m_info.pchEndRead - m_info.pchNext >= 1);
  }
  else
  {
    if (m_info.hmmio != NULL && cch > 0) {
      result = _hread((HFILE)m_info.hmmio, pch, cch);
      if (result == -1) {
        result = 0;
        m_info.lDiskOffset = GetCurrentOffset();
      }
      else
      {
        m_info.lDiskOffset += result;
      }
    }
  }

  return result;
}

// First attemp, not particularly close, see some sensible logic of what the 
// function is trying to do.
// OFFSET: LEGO1 0x100cca00
LONG MXIOINFO::Seek(LONG lOffset, int iOrigin)
{
  LONG result = -1;
  if (m_info.pchBuffer != NULL)
  {
    // Convert to SEEK_SET
    if (iOrigin == SEEK_CUR) {
      if (lOffset == 0) {
        // Nothing to do
        return (LONG)(m_info.pchNext + m_info.lBufOffset - m_info.pchBuffer);
      } else {
        iOrigin = 0;
        lOffset = (LONG)(m_info.pchNext + lOffset + m_info.lBufOffset - m_info.pchBuffer);
      }
    } else if (iOrigin == SEEK_END) {
      // Not implemented
      return -1;
    }

    // Seek distance is already within the buffer
    if ((m_info.lBufOffset <= lOffset) && (lOffset < m_info.cchBuffer + m_info.lBufOffset)) {
      m_info.pchNext = m_info.pchBuffer + lOffset - m_info.lBufOffset;
      return lOffset;
    }

    // Do SEEK_CUR on the underlying file handle
    if (m_info.hmmio != NULL) {
      short result = Flush(0);
      if (result == 0) {
        LONG newOffset = _llseek((HFILE)m_info.hmmio, lOffset, iOrigin);
        m_info.lDiskOffset = newOffset;
        if (newOffset == -1) {
          m_info.lDiskOffset = GetCurrentOffset();
          return -1;
        }
        LONG wholeBlockOffset = lOffset - (int)(lOffset % m_info.cchBuffer);
        m_info.lBufOffset = wholeBlockOffset;
        if (lOffset != wholeBlockOffset) {
          LONG newOffset2 = _llseek((HFILE)m_info.hmmio, wholeBlockOffset, 0);
          m_info.lDiskOffset = newOffset2;
          if (newOffset2 == -1) {
            m_info.lDiskOffset = GetCurrentOffset();
          }
        }
        if (m_info.lDiskOffset == m_info.lBufOffset) {
          DWORD rw = m_info.dwFlags & MMIO_RWMODE;
          if (rw != MMIO_READ && rw != MMIO_READWRITE) {
            m_info.pchNext = m_info.pchBuffer + lOffset - m_info.lBufOffset;
            return lOffset;
          }
          LONG bytesRead = _hread((HFILE)m_info.hmmio, m_info.pchBuffer, m_info.cchBuffer);
          if (bytesRead == -1) {
            m_info.lDiskOffset = GetCurrentOffset();
            return -1;
          }
          m_info.lDiskOffset += bytesRead;
          m_info.pchNext = m_info.pchBuffer + lOffset - m_info.lBufOffset;
          m_info.pchEndRead = m_info.pchBuffer + bytesRead;
          if (m_info.pchNext < m_info.pchEndRead) {
            return lOffset;
          }
        }
      }
    }
  }
  else
  {
    if (m_info.hmmio != NULL) {
      if ((iOrigin == SEEK_CUR) && (lOffset == 0)) {
        return m_info.lDiskOffset;
      }
      result = _llseek((HFILE)m_info.hmmio, lOffset, iOrigin);
      m_info.lDiskOffset = result;
      if (result == HFILE_ERROR) {
        m_info.lDiskOffset = GetCurrentOffset();
      }
    }
  }
  return result;
}

// Matching except for swap of EAX and ECX
// OFFSET: LEGO1 0x100ccbc0
unsigned short MXIOINFO::SetBuffer(LPSTR pchBuffer, LONG cchBuffer, UINT fuBuffer)
{
  unsigned short ret = Flush(0);
  if (m_info.dwFlags & MMIO_ALLOCBUF)
  {
    m_info.dwFlags &= ~MMIO_ALLOCBUF;
    free(m_info.pchBuffer);
  }
  m_info.pchBuffer = pchBuffer;
  m_info.cchBuffer = cchBuffer;
  m_info.pchEndRead = pchBuffer;
  m_info.pchEndWrite = pchBuffer + cchBuffer;
  return ret;
}

// OFFSET: LEGO1 0x100cce60
unsigned short MXIOINFO::Descend(LPMMCKINFO pmmcki, const MMCKINFO *pmmckiParent, UINT fuDescend)
{
  return 0;
}

// Not a close match, but the behavior looks reasonable.
// OFFSET: LEGO1 0x100ccc10
unsigned short MXIOINFO::Flush(int arg)
{
  unsigned short result = 0;
  if (m_info.dwFlags & MMIO_DIRTY)
  {
    if (m_info.pchBuffer == NULL) 
    {
      result = MMIOERR_UNBUFFERED;
    }
    else
    {
      if (m_info.hmmio == NULL || (m_info.dwFlags & MMIO_RWMODE) == 0)
      {
        return MMIOERR_CANNOTWRITE;
      }
      if (m_info.cchBuffer > 0)
      {
        if (m_info.lDiskOffset != m_info.lBufOffset)
        {
          m_info.lDiskOffset = _llseek((HFILE)m_info.hmmio, m_info.lBufOffset, 0);
        }
        if (m_info.lBufOffset == m_info.lDiskOffset)
        {
          long written = _hwrite((HFILE)m_info.hmmio, m_info.pchBuffer, m_info.cchBuffer);
          if (written != -1 && m_info.cchBuffer == written)
          {
            m_info.lDiskOffset += written;
            m_info.dwFlags &= ~MMIO_DIRTY;
            m_info.pchNext = m_info.pchBuffer;
            return 0;
          }
          m_info.lDiskOffset = GetCurrentOffset();
          return MMIOERR_CANNOTWRITE;
        }
        m_info.lDiskOffset = GetCurrentOffset();
        return MMIOERR_CANNOTSEEK;
      }
    }
  }
  return result;
}

// 97% Match, just two locations have the order of an == comparison swapped.
// I suspect this isn't how the code was originally written, because I have to
// include an empty if branch to get the code almost matching, though it is a
// place where you logically could have an empty block.
// OFFSET: LEGO1 0x100ccd00
unsigned short MXIOINFO::Something(UINT flags)
{
  short result = 0;
  DWORD rwState = m_info.dwFlags & MMIO_RWMODE;
  if (m_info.pchBuffer != NULL)
  {
    LONG cchBuffer = m_info.cchBuffer;
    if (((rwState == MMIO_WRITE) || (rwState == MMIO_READWRITE)) && (m_info.dwFlags & MMIO_DIRTY))
    {
      if (((flags & MMIO_WRITE) || (rwState == MMIO_READWRITE)) && (cchBuffer > 0))
      {
        if (m_info.lDiskOffset != m_info.lBufOffset) {
          m_info.lDiskOffset = _llseek((HFILE)m_info.hmmio, m_info.lBufOffset, 0);
        }
        if (m_info.lDiskOffset != m_info.lBufOffset)
        {
          result = MMIOERR_CANNOTSEEK;
          m_info.lDiskOffset = GetCurrentOffset();
        }
        else
        {
          LONG bytesWritten = _hwrite((HFILE)m_info.hmmio, m_info.pchBuffer, cchBuffer);
          if ((bytesWritten != -1) && (cchBuffer == bytesWritten)) {
            m_info.lDiskOffset += bytesWritten;
            m_info.dwFlags = m_info.dwFlags & ~MMIO_DIRTY;
            m_info.pchNext = m_info.pchBuffer;
            m_info.pchEndRead = m_info.pchBuffer;
          }
          else
          {
            result = MMIOERR_CANNOTWRITE;
            m_info.lDiskOffset = GetCurrentOffset();
          }
        }
      }
    }

    m_info.lBufOffset = m_info.lBufOffset + cchBuffer;
    if (((rwState != MMIO_READ) && (rwState != MMIO_READWRITE)) || cchBuffer <= 0) {
      // Nothing to do
    }
    else
    {
      if (m_info.lDiskOffset != m_info.lBufOffset) {
        m_info.lDiskOffset = _llseek((HFILE)m_info.hmmio, m_info.lBufOffset, 0);
      }
      if (m_info.lDiskOffset != m_info.lBufOffset) {
        result = MMIOERR_CANNOTSEEK;
        m_info.lDiskOffset = GetCurrentOffset();
      } else {
        LONG bytesRead = _hread((HFILE)m_info.hmmio, m_info.pchBuffer, cchBuffer);
        if (bytesRead == -1) {
          result = MMIOERR_CANNOTREAD;
          m_info.lDiskOffset = GetCurrentOffset();
        } else {
          m_info.lDiskOffset += bytesRead;
          m_info.pchNext = m_info.pchBuffer;
          m_info.pchEndRead = m_info.pchBuffer + bytesRead;
          return result;
        }
      }
    }
  }
  else
  {
    result = MMIOERR_UNBUFFERED;
  }
  return result;
}