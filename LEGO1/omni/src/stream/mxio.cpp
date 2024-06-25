#include "mxio.h"

#include "decomp.h"

#include <assert.h>

// This class should be 72 bytes in size, same as the MMIOINFO struct.
// The current implementation has MMIOINFO as the only member of the class,
// but this assert will enforce the size if we decide to change that.
DECOMP_SIZE_ASSERT(MXIOINFO, sizeof(MMIOINFO));

#ifdef MXIO_MINFO_MFILE
#define ASSIGN_M_FILE(X) m_info.hmmio = (HMMIO) (X)
#define M_FILE (HFILE)(m_info.hmmio)
#define RAW_M_FILE m_info.hmmio
#else
#define ASSIGN_M_FILE(X) m_file = (X)
#define M_FILE (m_file)
#define RAW_M_FILE m_file
#endif

// FUNCTION: LEGO1 0x100cc800
// FUNCTION: BETA10 0x1015e140
MXIOINFO::MXIOINFO()
{
	memset(&m_info, 0, sizeof(m_info));
}

// FUNCTION: LEGO1 0x100cc820
// FUNCTION: BETA10 0x1015e169
MXIOINFO::~MXIOINFO()
{
	Close(0);
}

// FUNCTION: LEGO1 0x100cc830
// FUNCTION: BETA10 0x1015e189
MxU16 MXIOINFO::Open(const char* p_filename, MxULong p_flags)
{
	OFSTRUCT unused;
	MxU16 result = 0;

	m_info.lDiskOffset = m_info.lBufOffset = 0;

	// DECOMP: Cast of p_flags to u16 forces the `movzx` instruction
	// original: m_info.hmmio = OpenFile(p_filename, &unused, (MxU16) p_flags);
	ASSIGN_M_FILE(OpenFile(p_filename, &unused, (MxU16) p_flags));

	if (M_FILE != HFILE_ERROR) {
		m_info.dwFlags = p_flags;
		if (m_info.dwFlags & MMIO_ALLOCBUF) {

			// Default buffer length of 8k if none specified
			MxLong len = m_info.cchBuffer;
			if (len == 0) {
				len = 8192;
			}

			char* buf = new char[len];

			if (!buf) {
				m_info.dwFlags &= ~MMIO_ALLOCBUF;
				m_info.cchBuffer = 0;
				m_info.pchBuffer = 0;
				result = MMIOERR_OUTOFMEMORY;
			}
			else {
				m_info.cchBuffer = len;
				m_info.pchBuffer = (HPSTR) buf;
			}

			m_info.pchNext = m_info.pchEndRead = m_info.pchBuffer;
			m_info.pchEndWrite = m_info.pchBuffer + m_info.cchBuffer;
		}
	}
	else {
		result = MMIOERR_CANNOTOPEN;
	}

	return result;
}

// FUNCTION: LEGO1 0x100cc8e0
// FUNCTION: BETA10 0x1015e30b
MxU16 MXIOINFO::Close(MxLong p_unused)
{
	MxU16 result = 0;

	if (RAW_M_FILE) {
		result = Flush(0);
		_lclose(M_FILE);
		ASSIGN_M_FILE(0);

		if (m_info.dwFlags & MMIO_ALLOCBUF) {
			delete[] m_info.pchBuffer;
		}

		m_info.pchBuffer = m_info.pchEndRead = m_info.pchEndWrite = NULL;
		m_info.dwFlags = 0;
	}

	return result;
}

// FUNCTION: LEGO1 0x100cc930
// FUNCTION: BETA10 0x1015e3b2
MxLong MXIOINFO::Read(void* p_buf, MxLong p_len)
{
	MxLong bytesRead = 0;

	if (m_info.pchBuffer) {

		MxLong bytesLeft = m_info.pchEndRead - m_info.pchNext;
		while (p_len > 0) {

			if (bytesLeft > 0) {
				if (p_len < bytesLeft) {
					bytesLeft = p_len;
				}

				memcpy(p_buf, m_info.pchNext, bytesLeft);

				m_info.pchNext += bytesLeft;
				bytesRead += bytesLeft;
				p_len -= bytesLeft;
			}

			if (p_len > 0) {
				if (Advance(MMIO_READ)) {
					break;
				}
				else {
					bytesLeft = m_info.pchEndRead - m_info.pchNext;
					if (bytesLeft <= 0) {
						break;
					}
				}
			}
		}
	}
	else if (RAW_M_FILE && p_len > 0) {
		bytesRead = _hread(M_FILE, p_buf, p_len);

		if (bytesRead == -1) {
			bytesRead = 0;
			m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
		else {
			m_info.lDiskOffset += bytesRead;
		}
	}

	return bytesRead;
}

// FUNCTION: BETA10 0x1015e4fc
MxLong MXIOINFO::Write(void* p_buf, MxLong p_len)
{
	MxLong bytesWritten = 0;

	if (m_info.pchBuffer) {

		MxLong bytesLeft = m_info.pchEndWrite - m_info.pchNext;
		while (p_len > 0) {

			if (bytesLeft > 0) {
				if (p_len < bytesLeft) {
					bytesLeft = p_len;
				}

				memcpy(m_info.pchNext, p_buf, bytesLeft);
				m_info.dwFlags |= MMIO_DIRTY;

				m_info.pchNext += bytesLeft;
				bytesWritten += bytesLeft;
				p_len -= bytesLeft;
			}

			if (p_len > 0) {
				if (Advance(MMIO_WRITE)) {
					assert(0);
					break;
				}
				else {
					bytesLeft = m_info.pchEndWrite - m_info.pchNext;
					if (bytesLeft <= 0) {
						assert(0);
						break;
					}
				}
			}
		}
	}
	else if (RAW_M_FILE && p_len > 0) {
		bytesWritten = _hwrite(M_FILE, (const char*) p_buf, p_len);

		if (bytesWritten == -1) {
			bytesWritten = 0;
			m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
		else {
			m_info.lDiskOffset += bytesWritten;
		}
	}

	// DECOMP: This assert is just "pchNext <= pchEndWrite"
	// That would suggest that MXIOINFO directly extends MMIOINFO.
	// TODO: Change that if we still have entropy at the end.
	assert(m_info.pchNext <= m_info.pchEndWrite);
	return bytesWritten;
}

// FUNCTION: LEGO1 0x100cca00
// FUNCTION: BETA10 0x1015e6c4
MxLong MXIOINFO::Seek(MxLong p_offset, MxLong p_origin)
{
	MxLong result = -1;
	MxLong bytesRead;

	// If buffered I/O
	if (m_info.pchBuffer) {
		if (p_origin == SEEK_CUR) {
			if (!p_offset) {
				// don't seek at all and just return where we are.
				return m_info.lBufOffset + (m_info.pchNext - m_info.pchBuffer);
			}

			// With SEEK_CUR, p_offset is a relative offset.
			// Get the absolute position instead and use SEEK_SET.
			p_offset += m_info.lBufOffset + (m_info.pchNext - m_info.pchBuffer);
			p_origin = SEEK_SET;
		}
		else if (p_origin == SEEK_END) {
			// not possible with buffered I/O
			return -1;
		}

		// else p_origin == SEEK_SET.

		// is p_offset between the start and end of the buffer?
		// i.e. can we do the seek without reading more from disk?
		if (p_offset >= m_info.lBufOffset && p_offset < m_info.lBufOffset + m_info.cchBuffer) {
			m_info.pchNext = m_info.pchBuffer + (p_offset - m_info.lBufOffset);
			result = p_offset;
		}
		else {
			// we have to read another chunk from disk.
			if (RAW_M_FILE && !Flush(0)) {
				m_info.lDiskOffset = _llseek(M_FILE, p_offset, p_origin);

				if (m_info.lDiskOffset == -1) {
					m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {

					// align offset to buffer size
					m_info.lBufOffset = p_offset - (p_offset % m_info.cchBuffer);

					// do we need to seek again?
					// (i.e. are we already aligned to buffer size?)
					if (p_offset != m_info.lBufOffset) {
						m_info.lDiskOffset = _llseek(M_FILE, m_info.lBufOffset, SEEK_SET);

						if (m_info.lDiskOffset == -1) {
							m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						}
					}

					if (m_info.lBufOffset == m_info.lDiskOffset) {
						// is the file open for writing only?
						if ((m_info.dwFlags & MMIO_RWMODE) == 0 || (m_info.dwFlags & MMIO_RWMODE) == MMIO_READWRITE) {
							// We can read from the file. Fill the buffer.
							bytesRead = _hread(M_FILE, m_info.pchBuffer, m_info.cchBuffer);

							if (bytesRead == -1) {
								m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
							}
							else {
								m_info.lDiskOffset += bytesRead;
								m_info.pchNext = p_offset - m_info.lBufOffset + m_info.pchBuffer;
								m_info.pchEndRead = m_info.pchBuffer + bytesRead;

								if (m_info.pchNext < m_info.pchEndRead) {
									result = p_offset;
								}
							}
						}
						else {
							m_info.pchNext = p_offset - m_info.lBufOffset + m_info.pchBuffer;
							result = p_offset;
						}
					}
				}
			}
		}
	}
	else if (RAW_M_FILE) {
		// No buffer so just seek the file directly (if we have a valid handle)
		// i.e. if we just want to get the current file position
		if (p_origin == SEEK_CUR && p_offset == 0) {
			return m_info.lDiskOffset;
		}

		m_info.lDiskOffset = _llseek(M_FILE, p_offset, p_origin);

		result = m_info.lDiskOffset;

		if (result == -1) {
			m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100ccbc0
// FUNCTION: BETA10 0x1015e9ad
MxU16 MXIOINFO::SetBuffer(char* p_buf, MxLong p_len, MxLong p_unused)
{
	MxU16 result = 0;
	result = Flush(0);

	if (m_info.dwFlags & MMIO_ALLOCBUF) {
		m_info.dwFlags &= ~MMIO_ALLOCBUF;
		delete[] m_info.pchBuffer;
	}

	m_info.pchBuffer = p_buf;
	m_info.cchBuffer = p_len;
	m_info.pchEndWrite = m_info.pchBuffer + m_info.cchBuffer;
	m_info.pchEndRead = m_info.pchBuffer;

	return result;
}

// FUNCTION: LEGO1 0x100ccc10
// FUNCTION: BETA10 0x1015ea3e
MxU16 MXIOINFO::Flush(MxU16 p_unused)
{
	MxU16 result = 0;
	MxLong bytesWritten;

	// if buffer is dirty
	if (m_info.dwFlags & MMIO_DIRTY) {
		// if we have allocated an IO buffer
		if (m_info.pchBuffer) {
			// if we have a file open for writing
			if (RAW_M_FILE && (m_info.dwFlags & MMIO_RWMODE)) {
				// DECOMP: pulling this value out into a variable forces it into EBX
				MxLong cchBuffer = m_info.cchBuffer;
				if (cchBuffer > 0) {
					if (m_info.lBufOffset != m_info.lDiskOffset) {
						m_info.lDiskOffset = _llseek(M_FILE, m_info.lBufOffset, SEEK_SET);
					}

					// Was the previous seek (if required) successful?
					if (m_info.lBufOffset != m_info.lDiskOffset) {
						result = MMIOERR_CANNOTSEEK;
						m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
					}
					else {
						bytesWritten = _hwrite(M_FILE, m_info.pchBuffer, cchBuffer);

						if (bytesWritten == -1 || bytesWritten != cchBuffer) {
							result = MMIOERR_CANNOTWRITE;
							m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						}
						else {
							m_info.lDiskOffset += bytesWritten;
							m_info.pchNext = m_info.pchBuffer;
							m_info.dwFlags &= ~MMIO_DIRTY;
						}
					}
				}
			}
			else {
				result = MMIOERR_CANNOTWRITE;
			}
		}
		else {
			result = MMIOERR_UNBUFFERED;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100ccd00
// FUNCTION: BETA10 0x1015eb8f
MxU16 MXIOINFO::Advance(MxU16 p_option)
{
	MxU16 result = 0;
	MxULong rwmode = m_info.dwFlags & MMIO_RWMODE;

	if (m_info.pchBuffer) {
		MxLong cch = m_info.cchBuffer;
		MxLong bytesCounter;

		// If we can and should write to the file,
		// if we are being asked to write to the file,
		// and if there is a buffer *to* write:
		if ((rwmode == MMIO_WRITE || rwmode == MMIO_READWRITE) && (m_info.dwFlags & MMIO_DIRTY) &&
			((p_option & MMIO_WRITE) || (rwmode == MMIO_READWRITE)) && cch > 0) {

			if (m_info.lBufOffset != m_info.lDiskOffset) {
				m_info.lDiskOffset = _llseek(M_FILE, m_info.lBufOffset, SEEK_SET);
			}

			if (m_info.lBufOffset != m_info.lDiskOffset) {
				result = MMIOERR_CANNOTSEEK;
				m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
			}
			else {
				bytesCounter = _hwrite(M_FILE, m_info.pchBuffer, cch);

				if (bytesCounter == -1 || bytesCounter != cch) {
					result = MMIOERR_CANNOTWRITE;
					m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {
					m_info.lDiskOffset += bytesCounter;
					m_info.pchNext = m_info.pchBuffer;
					m_info.pchEndRead = m_info.pchBuffer;
					m_info.dwFlags &= ~MMIO_DIRTY;
				}
			}
		}

		m_info.lBufOffset += cch;
		if ((!rwmode || rwmode == MMIO_READWRITE) && cch > 0) {
			if (m_info.lBufOffset != m_info.lDiskOffset) {
				m_info.lDiskOffset = _llseek(M_FILE, m_info.lBufOffset, SEEK_SET);
			}

			// if previous seek failed
			if (m_info.lBufOffset != m_info.lDiskOffset) {
				result = MMIOERR_CANNOTSEEK;
				m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
			}
			else {
				bytesCounter = _hread(M_FILE, m_info.pchBuffer, cch);

				if (bytesCounter == -1) {
					result = MMIOERR_CANNOTREAD;
					m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {
					m_info.lDiskOffset += bytesCounter;
					m_info.pchNext = m_info.pchBuffer;
					m_info.pchEndRead = m_info.pchBuffer + bytesCounter;
				}
			}
		}
	}
	else {
		result = MMIOERR_UNBUFFERED;
	}

	return result;
}

// FUNCTION: LEGO1 0x100cce60
// FUNCTION: BETA10 0x1015edef
MxU16 MXIOINFO::Descend(MMCKINFO* p_chunkInfo, const MMCKINFO* p_parentInfo, MxU16 p_descend)
{
	MxU16 result = 0;
	MxULong ofs;
	BOOL readOk;

	if (!p_chunkInfo) {
		return MMIOERR_BASE; // ?
	}

	if (!p_descend) {
		p_chunkInfo->dwFlags = 0;
		if (Read(p_chunkInfo, 8) != 8) {
			result = MMIOERR_CANNOTREAD;
		}
		else {
			if (m_info.pchBuffer) {
				p_chunkInfo->dwDataOffset = m_info.pchNext - m_info.pchBuffer + m_info.lBufOffset;
			}
			else {
				p_chunkInfo->dwDataOffset = m_info.lDiskOffset;
			}

			if ((p_chunkInfo->ckid == FOURCC_RIFF || p_chunkInfo->ckid == FOURCC_LIST) &&
				Read(&p_chunkInfo->fccType, 4) != 4) {
				result = MMIOERR_CANNOTREAD;
			}
		}
	}
	else {
		ofs = MAXLONG;

		if (p_parentInfo) {
			ofs = p_parentInfo->cksize + p_parentInfo->dwDataOffset;
		}

		BOOL running = TRUE;
		readOk = FALSE;
		MMCKINFO tmp;
		tmp.dwFlags = 0;

		while (running) {
			if (Read(&tmp, 8) != 8) {
				// If the first read fails, report read error. Else EOF.
				result = readOk ? MMIOERR_CHUNKNOTFOUND : MMIOERR_CANNOTREAD;
				running = FALSE;
			}
			else {
				readOk = TRUE;
				if (m_info.pchBuffer) {
					tmp.dwDataOffset = m_info.pchNext - m_info.pchBuffer + m_info.lBufOffset;
				}
				else {
					tmp.dwDataOffset = m_info.lDiskOffset;
				}

				if (ofs < tmp.dwDataOffset) {
					result = MMIOERR_CHUNKNOTFOUND;
					running = FALSE;
				}
				else if ((p_descend == MMIO_FINDLIST && tmp.ckid == FOURCC_LIST) || (p_descend == MMIO_FINDRIFF && tmp.ckid == FOURCC_RIFF)) {
					if (Read(&tmp.fccType, 4) != 4) {
						result = MMIOERR_CANNOTREAD;
						running = FALSE;
					}
					else if (p_chunkInfo->fccType == tmp.fccType) {
						running = FALSE;
					}
				}
				else if (p_chunkInfo->ckid == tmp.ckid) {
					running = FALSE;
				}
				else if (Seek((tmp.cksize & 1) + tmp.cksize, SEEK_CUR) == -1) {
					result = MMIOERR_CANNOTSEEK;
					running = FALSE;
				}
			}
		}

		if (!result) {
			// implicit memcpy
			*p_chunkInfo = tmp;
		}
	}

	return result;
}

// FUNCTION: BETA10 0x1015f08b
MxU16 MXIOINFO::Ascend(MMCKINFO* p_chunkInfo, MxU16 p_ascend)
{
	MxLong ofs;
	MxULong size;
	MxU16 result = 0;

	if (p_chunkInfo == NULL) {
		return MMIOERR_BASE;
	}

	if (m_info.dwFlags & MMIO_RWMODE) {
		if (m_info.pchBuffer) {
			size = (MxULong) (m_info.pchNext - m_info.pchBuffer) + m_info.lBufOffset - p_chunkInfo->dwDataOffset;
		}
		else {
			size = m_info.lDiskOffset - p_chunkInfo->dwDataOffset;
		}

		// Write a zero byte if the chunk size is odd
		if (size & 1) {
			Write(&result, 1);
		}

		if ((p_chunkInfo->dwFlags & MMIO_DIRTY) && p_chunkInfo->cksize != size) {
			ofs = p_chunkInfo->dwDataOffset - 4;
			// Correct chunk size
			p_chunkInfo->cksize = size;
			p_chunkInfo->dwFlags &= ~MMIO_DIRTY;

			// Now write the corrected size
			if (m_info.pchBuffer && ofs >= m_info.lBufOffset && m_info.cchBuffer + m_info.lBufOffset > ofs) {
				memcpy(m_info.pchBuffer + (ofs - m_info.lBufOffset), (char*) &size, 4);
				m_info.dwFlags |= MMIO_DIRTY;
			}
			else {
				m_info.lDiskOffset = _llseek(M_FILE, ofs, SEEK_SET);

				if (m_info.lDiskOffset == ofs) {
					if (_lwrite(M_FILE, (char*) &size, 4) != 4) {
						m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						result = MMIOERR_CANNOTWRITE;
					}
					else {
						m_info.lDiskOffset += 4; // TODO: compiler weirdness?
					}
				}
				else {
					m_info.lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
					result = MMIOERR_CANNOTSEEK;
				}
			}
		}
	}

	// Seek past the end of the chunk (plus optional pad byte if size is odd)
	if (result == 0 &&
		Seek((p_chunkInfo->cksize & 1) + p_chunkInfo->cksize + p_chunkInfo->dwDataOffset, SEEK_SET) == -1) {
		result = MMIOERR_CANNOTSEEK;
	}

	return result;
}
