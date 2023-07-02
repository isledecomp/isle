#include "mxioinfo.h"

// OFFSET: LEGO1 0x100cc800
MXIOINFO::MXIOINFO()
{
  // This is not good practice, but shouldn't damage anything
  // because MXIOINFO has no vtable.
  memset(this, 0, sizeof(*this));
}

// OFFSET: LEGO1 0x100cc820
MXIOINFO::~MXIOINFO()
{
  Close(0);
}

// OFFSET: LEGO1 0x100cc830
MxU16 MXIOINFO::Open(const char *filename, DWORD fdwOpen)
{
  OFSTRUCT _unused;
  MxU16 result = 0;

  m_lBufOffset = 0;
  m_lDiskOffset = 0;

  // Cast of fdWOpen to u16 forces the `movzx` instruction
  //m_hmmio = OpenFile(filename, &_unused, (unsigned short)fdwOpen);
  m_hmmio = OpenFile(filename, &_unused, fdwOpen);
  
  if (m_hmmio != HFILE_ERROR) {
    m_dwFlags = fdwOpen;
    if (fdwOpen & MMIO_ALLOCBUF) {

      // Default buffer length of 8k if none specified
      int len = m_cchBuffer ? m_cchBuffer : 8192;
      HPSTR buf = new char[len];

      if (!buf) {
        result = MMIOERR_OUTOFMEMORY;
        m_cchBuffer = 0;
        m_dwFlags &= ~MMIO_ALLOCBUF;
        m_pchBuffer = 0;
      } else {
        m_pchBuffer = buf;
        m_cchBuffer = len;
      }

      m_pchEndRead = m_pchBuffer;
      m_pchNext = m_pchBuffer;
      m_pchEndWrite = m_pchBuffer + m_cchBuffer;
    }
  } else {
    result = MMIOERR_CANNOTOPEN;
  }

  return result;
}

// OFFSET: LEGO1 0x100cc8e0
MxU16 MXIOINFO::Close(MxLong arg)
{
  MxU16 result = 0;

  if (m_hmmio) {
    result = Flush(0);
    _lclose(m_hmmio);
    m_hmmio = NULL;

    if (m_dwFlags & MMIO_ALLOCBUF)
      delete[] m_pchBuffer;

    m_pchEndWrite = 0;
    m_pchEndRead = 0;
    m_pchBuffer = 0;
    m_dwFlags = 0;
  }

  return result;
}

// OFFSET: LEGO1 0x100cc930
MxLong MXIOINFO::Read(HPSTR pch, LONG cch)
{
  MxLong bytes_read = 0;

  if (m_pchBuffer) {

    int bytes_left = m_pchEndRead - m_pchNext;
    while (cch > 0) {

      if (bytes_left > 0) {
        if (cch < bytes_left)
          bytes_left = cch;
        
        memcpy(pch, m_pchNext, bytes_left);
        cch -= bytes_left;
        
        m_pchNext += bytes_left;
        bytes_read += bytes_left;
      }

      if (cch <= 0 || Advance(0))
        break;

      bytes_left = m_pchEndRead - m_pchNext;
      if (bytes_left <= 0)
        break;
    }
  } else if (m_hmmio && cch > 0) {
    bytes_read = _hread(m_hmmio, pch, cch);

    if (bytes_read == -1) {
      bytes_read = 0;
      m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
    } else {
      m_lDiskOffset += bytes_read;
    }
  }

  return bytes_read;
}

// OFFSET: LEGO1 0x100cca00
MxLong MXIOINFO::Seek(LONG lOffset, int iOrigin)
{
  MxLong result = -1;

  // If buffered I/O
  if (m_pchBuffer) {
    if (iOrigin == SEEK_CUR) {
      if (!lOffset) {
        // don't seek at all and just return where we are.
        return m_lBufOffset + (m_pchNext - m_pchBuffer);
      } else {
        // With SEEK_CUR, lOffset is a relative offset.
        // Get the absolute position instead and use SEEK_SET.
        lOffset += m_lBufOffset + (m_pchNext - m_pchBuffer);
        iOrigin = SEEK_SET;
      }
    } else if (iOrigin == SEEK_END) {
      // not possible with buffered I/O
      return -1;
    }
    
    // else iOrigin == SEEK_SET.

    // is lOffset between the start and end of the buffer?
    // i.e. can we do the seek without reading more from disk?
    if (lOffset >= m_lBufOffset && lOffset < m_lBufOffset + m_cchBuffer) {
      m_pchNext = m_pchBuffer + (lOffset - m_lBufOffset);
      result = lOffset;
    } else {
      // we have to read another chunk from disk.
      if (m_hmmio && !Flush(0)) {
        m_lDiskOffset = _llseek(m_hmmio, lOffset, iOrigin);

        if (m_lDiskOffset == -1) {
          m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
        } else {

          // align offset to buffer size
          int new_offset = lOffset - (lOffset % m_cchBuffer);
          m_lBufOffset = new_offset;

          // do we need to seek again?
          // (i.e. are we already aligned to buffer size?)
          if (lOffset != new_offset) {
            m_lDiskOffset = _llseek(m_hmmio, new_offset, SEEK_SET);

            if (m_lDiskOffset == -1) {
              m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
            }
          }

          if (m_lBufOffset == m_lDiskOffset) {
            // is the file open for writing only?
            if ((m_dwFlags & MMIO_RWMODE) &&
                ((m_dwFlags & MMIO_RWMODE) != MMIO_READWRITE)) {

              m_pchNext = m_pchBuffer - m_lBufOffset + lOffset;
              
              result = lOffset;
            } else {
              // We can read from the file. Fill the buffer.
              int bytes_read = _hread(m_hmmio, m_pchBuffer, m_cchBuffer);
              
              if (bytes_read == -1) {
                m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
              } else {
                m_lDiskOffset += bytes_read;
                m_pchNext = lOffset - m_lBufOffset + m_pchBuffer;
                m_pchEndRead = m_pchBuffer + bytes_read;

                if (m_pchNext < m_pchEndRead) {
                  result = lOffset;
                }
              }
            }
          }
        }
      }
    }
  } else {
    // No buffer so just seek the file directly (if we have a valid handle)
    if (m_hmmio) {
      // i.e. if we just want to get the current file position
      if (iOrigin == SEEK_CUR && lOffset == 0) {
        return m_lDiskOffset;
      } else {
        m_lDiskOffset = _llseek(m_hmmio, lOffset, iOrigin);

        result = m_lDiskOffset;

        if (result == -1) {
          m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
        }
      }
    }
  }

  return result;
}

// OFFSET: LEGO1 0x100ccbc0
MxU16 MXIOINFO::SetBuffer(LPSTR pchBuffer, LONG cchBuffer, LONG unk)
{
  MxU16 result = Flush(0);

  if (m_dwFlags & MMIO_ALLOCBUF) {
    m_dwFlags &= ~MMIO_ALLOCBUF;
    delete[] m_pchBuffer;
  }

  m_pchBuffer = pchBuffer;
  m_cchBuffer = cchBuffer;
  m_pchEndWrite = m_pchBuffer + m_cchBuffer;
  m_pchEndRead = m_pchBuffer;

  return result;
}

// OFFSET: LEGO1 0x100ccc10
MxU16 MXIOINFO::Flush(UINT fuFlush)
{
  MxU16 result = 0;

  // if buffer is dirty
  if (m_dwFlags & MMIO_DIRTY) {
    // if we have allocated an IO buffer
    if (m_pchBuffer) {
      // if we have a file open for writing
      if (m_hmmio && (m_dwFlags & MMIO_RWMODE)) {
        // (pulling this value out into a variable forces it into EBX)
        LONG cchBuffer = m_cchBuffer;
        if (cchBuffer > 0) {
          if (m_lBufOffset != m_lDiskOffset) {
            m_lDiskOffset = _llseek(m_hmmio, m_lBufOffset, SEEK_SET);
          }

          // Was the previous seek (if required) successful?
          if (m_lBufOffset != m_lDiskOffset) {
            result = MMIOERR_CANNOTSEEK;
            m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
          } else {
            long bytes_written = _hwrite(m_hmmio, m_pchBuffer, cchBuffer);

            if (bytes_written != -1 && bytes_written == cchBuffer) {
              m_lDiskOffset += bytes_written;
              m_pchNext = m_pchBuffer;
              m_dwFlags &= ~MMIO_DIRTY;
            } else {
              result = MMIOERR_CANNOTWRITE;
              m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
            }
          }
        }
      } else {
        result = MMIOERR_CANNOTWRITE;
      }
    } else {
      result = MMIOERR_UNBUFFERED;
    }
  }

  return result;
}

// OFFSET: LEGO1 0x100ccd00
MxU16 MXIOINFO::Advance(UINT fuAdvance)
{
  MxU16 result = 0;
  DWORD rwmode = m_dwFlags & MMIO_RWMODE;

  if (m_pchBuffer) {
    long cch = m_cchBuffer;

    // If we can and should write to the file,
    // if we are being asked to write to the file,
    // and if there is a buffer *to* write:
    if ((rwmode == MMIO_WRITE || rwmode == MMIO_READWRITE) &&
        (m_dwFlags & MMIO_DIRTY) && 
        ((fuAdvance & MMIO_WRITE) || (rwmode == MMIO_READWRITE)) &&
        cch > 0) {

      if (m_lBufOffset != m_lDiskOffset) {
        m_lDiskOffset = _llseek(m_hmmio, m_lBufOffset, SEEK_SET);
      }

      if (m_lBufOffset != m_lDiskOffset) {
        result = MMIOERR_CANNOTSEEK;
      } else {
        long bytes_written = _hwrite(m_hmmio, m_pchBuffer, cch);

        if (bytes_written != -1 && bytes_written == cch) {
          m_lDiskOffset += bytes_written;
          m_pchNext = m_pchBuffer;
          m_pchEndRead = m_pchBuffer;
          m_dwFlags &= ~MMIO_DIRTY;
        } else {
          result = MMIOERR_CANNOTWRITE;
        }
      }  

      m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);

    }

    m_lBufOffset += cch;
    if ((!rwmode || rwmode == MMIO_READWRITE) && cch > 0) {
      if (m_lBufOffset != m_lDiskOffset) {
        m_lDiskOffset = _llseek(m_hmmio, m_lBufOffset, SEEK_SET);
      }

      // if previous seek failed
      if (m_lBufOffset != m_lDiskOffset) {
        result = MMIOERR_CANNOTSEEK;
        m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
      } else {
        int bytes_read = _hread(m_hmmio, m_pchBuffer, cch);

        if (bytes_read == -1) {
          result = MMIOERR_CANNOTREAD;
          m_lDiskOffset = _llseek(m_hmmio, 0, SEEK_CUR);
        } else {
          m_lDiskOffset += bytes_read;
          m_pchNext = m_pchBuffer;
          m_pchEndRead = m_pchBuffer + bytes_read;
        }
      }
    }
  } else {
    result = MMIOERR_UNBUFFERED;
  }

  return result;
}

// OFFSET: LEGO1 0x100cce60
MxU16 MXIOINFO::Descend(MMCKINFO *pmmcki, const MMCKINFO *pmmckiParent, unsigned short fuDescend)
{
  unsigned short result = 0;
  
  if (!pmmcki) 
    return MMIOERR_BASE; // ?

  if (!fuDescend) {
    pmmcki->dwFlags = 0;
    if (Read((char *)pmmcki, 8) != 8) {
      result = MMIOERR_CANNOTREAD;
    } else {
      if (m_pchBuffer) {
        pmmcki->dwDataOffset = m_pchNext - m_pchBuffer + m_lBufOffset;
      } else {
        pmmcki->dwDataOffset = m_lDiskOffset;
      }

      if (pmmcki->ckid == FOURCC_RIFF || pmmcki->ckid == FOURCC_LIST) {
        if (Read((char *)&pmmcki->fccType, 4) != 4) {
          result = MMIOERR_CANNOTREAD;
        }
      }
    }
  } else {
    DWORD ofs = MAXLONG;

    if (pmmckiParent)
      ofs = pmmckiParent->cksize + pmmckiParent->dwDataOffset;

    BOOL running = TRUE;
    MMCKINFO tmp;
    BOOL read_ok = FALSE;
    tmp.dwFlags = 0;

    // This loop is... something
    do {
      if (Read((char *)&tmp, 8) != 8) {
        // If the first read fails, report read error. Else EOF.
        result = read_ok ? MMIOERR_CHUNKNOTFOUND : MMIOERR_CANNOTREAD;
        running = FALSE;
      } else {
        read_ok = TRUE;
        if (m_pchBuffer) {
          tmp.dwDataOffset = m_pchNext - m_pchBuffer + m_lBufOffset;
        } else {
          tmp.dwDataOffset = m_lDiskOffset;
        }

        if (ofs < tmp.dwDataOffset) {
          result = MMIOERR_CHUNKNOTFOUND;
          running = FALSE;
        } else {
          if ((fuDescend == MMIO_FINDLIST && tmp.ckid == FOURCC_LIST) ||
              (fuDescend == MMIO_FINDRIFF && tmp.ckid == FOURCC_RIFF)) {
            if (Read((char *)&tmp.fccType, 4) != 4) {
              result = MMIOERR_CANNOTREAD;
            } else {
              if (pmmcki->fccType != tmp.fccType)
                continue;
            }
            running = FALSE;
          } else {
            if (pmmcki->ckid != tmp.ckid) {
              if (Seek((tmp.cksize&1)+tmp.cksize, SEEK_CUR) != -1) {
                continue;
              } else {
                result = MMIOERR_CANNOTSEEK;
              }
            }
            running = FALSE;
          }
        }
      }

    } while (running);

    if (!result)
      memcpy(pmmcki, &tmp, sizeof(MMCKINFO));

  }

  return result;
}
