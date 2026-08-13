// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordXR {
	inline void Record() {}
};

class MxUnkRecordXS {
	inline void Record() {}
};

#include "mxio.h"

#include "decomp.h"

#include <assert.h>

// This class should be 72 bytes in size, same as the MMIOINFO struct.
// The current implementation has MMIOINFO as the only member of the class,
// but this assert will enforce the size if we decide to change that.
DECOMP_SIZE_ASSERT(MXIOINFO, sizeof(MMIOINFO));

#ifdef MXIO_MINFO_MFILE
#define ASSIGN_M_FILE(X) hmmio = (HMMIO) (X)
#define M_FILE (HFILE)(hmmio)
#define RAW_M_FILE hmmio
#else
#define ASSIGN_M_FILE(X) m_file = (X)
#define M_FILE (m_file)
#define RAW_M_FILE m_file
#endif

// FUNCTION: LEGO1 0x100cc800
// FUNCTION: BETA10 0x1015e140
MXIOINFO::MXIOINFO()
{
	memset(this, 0, sizeof(MXIOINFO));
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
	MxU16 result = MMSYSERR_NOERROR;

	lDiskOffset = lBufOffset = 0;

	// DECOMP: Cast of p_flags to u16 forces the `movzx` instruction
	// original: hmmio = OpenFile(p_filename, &unused, (MxU16) p_flags);
	ASSIGN_M_FILE(OpenFile(p_filename, &unused, (MxU16) p_flags));

	if (M_FILE != HFILE_ERROR) {
		dwFlags = p_flags;
		if (dwFlags & MMIO_ALLOCBUF) {

			// Default buffer length of 8k if none specified
			MxLong len = cchBuffer;
			if (len == 0) {
				len = 8192;
			}

			char* buf = new char[len];

			if (!buf) {
				dwFlags &= ~MMIO_ALLOCBUF;
				cchBuffer = 0;
				pchBuffer = 0;
				result = MMIOERR_OUTOFMEMORY;
			}
			else {
				cchBuffer = len;
				pchBuffer = (HPSTR) buf;
			}

			pchNext = pchEndRead = pchBuffer;
			pchEndWrite = pchBuffer + cchBuffer;
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
	MxU16 result = MMSYSERR_NOERROR;

	if (RAW_M_FILE) {
		result = Flush(0);
		_lclose(M_FILE);
		ASSIGN_M_FILE(0);

		if (dwFlags & MMIO_ALLOCBUF) {
			delete[] pchBuffer;
		}

		pchBuffer = pchEndRead = pchEndWrite = NULL;
		dwFlags = 0;
	}

	return result;
}

// FUNCTION: LEGO1 0x100cc930
// FUNCTION: BETA10 0x1015e3b2
MxLong MXIOINFO::Read(void* p_buf, MxLong p_len)
{
	MxLong bytesRead = 0;

	if (pchBuffer) {

		MxLong bytesLeft = pchEndRead - pchNext;
		while (p_len > 0) {

			if (bytesLeft > 0) {
				if (p_len < bytesLeft) {
					bytesLeft = p_len;
				}

				memcpy(p_buf, pchNext, bytesLeft);

				pchNext += bytesLeft;
				bytesRead += bytesLeft;
				p_len -= bytesLeft;
			}

			if (p_len > 0) {
				if (Advance(MMIO_READ)) {
					break;
				}
				else {
					bytesLeft = pchEndRead - pchNext;
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
			lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
		else {
			lDiskOffset += bytesRead;
		}
	}

	return bytesRead;
}

// FUNCTION: BETA10 0x1015e4fc
MxLong MXIOINFO::Write(void* p_buf, MxLong p_len)
{
	MxLong bytesWritten = 0;

	if (pchBuffer) {

		MxLong bytesLeft = pchEndWrite - pchNext;
		while (p_len > 0) {

			if (bytesLeft > 0) {
				if (p_len < bytesLeft) {
					bytesLeft = p_len;
				}

				memcpy(pchNext, p_buf, bytesLeft);
				dwFlags |= MMIO_DIRTY;

				pchNext += bytesLeft;
				bytesWritten += bytesLeft;
				p_len -= bytesLeft;
			}

			if (p_len > 0) {
				if (Advance(MMIO_WRITE)) {
					assert(0);
					break;
				}
				else {
					bytesLeft = pchEndWrite - pchNext;
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
			lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
		else {
			lDiskOffset += bytesWritten;
		}
	}

	// DECOMP: This assert is just "pchNext <= pchEndWrite"
	// That would suggest that MXIOINFO directly extends MMIOINFO.
	// TODO: Change that if we still have entropy at the end.
	assert(pchNext <= pchEndWrite);
	return bytesWritten;
}

// Declaration-record carrier: MXIOINFO::Advance is decided by the state
// accumulated at THIS point, not at the head of the unit -- a carrier seated
// before the includes reaches a strictly larger set of members and cannot
// reach Advance alone. Neutral stand-in pending better evidence.
class MxUnkRecordIO000;
class MxUnkRecordIO001;
class MxUnkRecordIO002;
class MxUnkRecordIO003;
class MxUnkRecordIO004;
class MxUnkRecordIO005;
class MxUnkRecordIO006;
class MxUnkRecordIO007;
class MxUnkRecordIO008;
class MxUnkRecordIO009;
class MxUnkRecordIO010;
class MxUnkRecordIO011;
class MxUnkRecordIO012;
class MxUnkRecordIO013;
class MxUnkRecordIO014;

// FUNCTION: LEGO1 0x100cca00
// FUNCTION: BETA10 0x1015e6c4
MxLong MXIOINFO::Seek(MxLong p_offset, MxLong p_origin)
{
	MxLong result = -1;
	MxLong bytesRead;

	// If buffered I/O
	if (pchBuffer) {
		if (p_origin == SEEK_CUR) {
			if (!p_offset) {
				// don't seek at all and just return where we are.
				return lBufOffset + (pchNext - pchBuffer);
			}

			// With SEEK_CUR, p_offset is a relative offset.
			// Get the absolute position instead and use SEEK_SET.
			p_offset += lBufOffset + (pchNext - pchBuffer);
			p_origin = SEEK_SET;
		}
		else if (p_origin == SEEK_END) {
			// not possible with buffered I/O
			return -1;
		}

		// else p_origin == SEEK_SET.

		// is p_offset between the start and end of the buffer?
		// i.e. can we do the seek without reading more from disk?
		if (p_offset >= lBufOffset && p_offset < lBufOffset + cchBuffer) {
			pchNext = pchBuffer + (p_offset - lBufOffset);
			result = p_offset;
		}
		else {
			// we have to read another chunk from disk.
			if (RAW_M_FILE && !Flush(0)) {
				lDiskOffset = _llseek(M_FILE, p_offset, p_origin);

				if (lDiskOffset == -1) {
					lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {

					// align offset to buffer size
					lBufOffset = p_offset - (p_offset % cchBuffer);

					// do we need to seek again?
					// (i.e. are we already aligned to buffer size?)
					if (p_offset != lBufOffset) {
						lDiskOffset = _llseek(M_FILE, lBufOffset, SEEK_SET);

						if (lDiskOffset == -1) {
							lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						}
					}

					if (lBufOffset == lDiskOffset) {
						// is the file open for writing only?
						if ((dwFlags & MMIO_RWMODE) == 0 || (dwFlags & MMIO_RWMODE) == MMIO_READWRITE) {
							// We can read from the file. Fill the buffer.
							bytesRead = _hread(M_FILE, pchBuffer, cchBuffer);

							if (bytesRead == -1) {
								lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
							}
							else {
								lDiskOffset += bytesRead;
								pchNext = p_offset - lBufOffset + pchBuffer;
								pchEndRead = pchBuffer + bytesRead;

								if (pchNext < pchEndRead) {
									result = p_offset;
								}
							}
						}
						else {
							pchNext = p_offset - lBufOffset + pchBuffer;
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
			return lDiskOffset;
		}

		lDiskOffset = _llseek(M_FILE, p_offset, p_origin);

		result = lDiskOffset;

		if (result == -1) {
			lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100ccbc0
// FUNCTION: BETA10 0x1015e9ad
MxU16 MXIOINFO::SetBuffer(char* p_buf, MxLong p_len, MxLong p_unused)
{
	MxU16 result = MMSYSERR_NOERROR;
	result = Flush(0);

	if (dwFlags & MMIO_ALLOCBUF) {
		dwFlags &= ~MMIO_ALLOCBUF;
		delete[] pchBuffer;
	}

	pchBuffer = p_buf;
	cchBuffer = p_len;
	pchEndWrite = pchBuffer + cchBuffer;
	pchEndRead = pchBuffer;

	return result;
}

// FUNCTION: LEGO1 0x100ccc10
// FUNCTION: BETA10 0x1015ea3e
MxU16 MXIOINFO::Flush(MxU16 p_unused)
{
	MxU16 result = MMSYSERR_NOERROR;
	MxLong bytesWritten;

	// if buffer is dirty
	if (dwFlags & MMIO_DIRTY) {
		// if we have allocated an IO buffer
		if (pchBuffer) {
			// if we have a file open for writing
			if (RAW_M_FILE && (dwFlags & MMIO_RWMODE)) {
				MxLong cch = cchBuffer;
				if (cch > 0) {
					if (lBufOffset != lDiskOffset) {
						lDiskOffset = _llseek(M_FILE, lBufOffset, SEEK_SET);
					}

					// Was the previous seek (if required) successful?
					if (lBufOffset != lDiskOffset) {
						result = MMIOERR_CANNOTSEEK;
						lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
					}
					else {
						bytesWritten = _hwrite(M_FILE, pchBuffer, cch);

						if (bytesWritten == -1 || bytesWritten != cch) {
							result = MMIOERR_CANNOTWRITE;
							lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						}
						else {
							lDiskOffset += bytesWritten;
							pchNext = pchBuffer;
							dwFlags &= ~MMIO_DIRTY;
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
	MxU16 result = MMSYSERR_NOERROR;
	MxULong rwmode = dwFlags & MMIO_RWMODE;

	if (pchBuffer) {
		MxLong cch = cchBuffer;
		MxLong bytesCounter;

		// If we can and should write to the file,
		// if we are being asked to write to the file,
		// and if there is a buffer *to* write:
		if ((rwmode == MMIO_WRITE || rwmode == MMIO_READWRITE) && (dwFlags & MMIO_DIRTY) &&
			((p_option & MMIO_WRITE) || (rwmode == MMIO_READWRITE)) && cch > 0) {

			if (lBufOffset != lDiskOffset) {
				lDiskOffset = _llseek(M_FILE, lBufOffset, SEEK_SET);
			}

			if (lBufOffset != lDiskOffset) {
				result = MMIOERR_CANNOTSEEK;
				lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
			}
			else {
				bytesCounter = _hwrite(M_FILE, pchBuffer, cch);

				if (bytesCounter == -1 || bytesCounter != cch) {
					result = MMIOERR_CANNOTWRITE;
					lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {
					lDiskOffset += bytesCounter;
					pchNext = pchBuffer;
					pchEndRead = pchBuffer;
					dwFlags &= ~MMIO_DIRTY;
				}
			}
		}

		lBufOffset += cch;
		if ((!rwmode || rwmode == MMIO_READWRITE) && cch > 0) {
			if (lBufOffset != lDiskOffset) {
				lDiskOffset = _llseek(M_FILE, lBufOffset, SEEK_SET);
			}

			// if previous seek failed
			if (lBufOffset != lDiskOffset) {
				result = MMIOERR_CANNOTSEEK;
				lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
			}
			else {
				bytesCounter = _hread(M_FILE, pchBuffer, cch);

				if (bytesCounter == -1) {
					result = MMIOERR_CANNOTREAD;
					lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
				}
				else {
					lDiskOffset += bytesCounter;
					pchNext = pchBuffer;
					pchEndRead = pchBuffer + bytesCounter;
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
	MxU16 result = MMSYSERR_NOERROR;
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
			if (pchBuffer) {
				p_chunkInfo->dwDataOffset = pchNext - pchBuffer + lBufOffset;
			}
			else {
				p_chunkInfo->dwDataOffset = lDiskOffset;
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
				if (pchBuffer) {
					tmp.dwDataOffset = pchNext - pchBuffer + lBufOffset;
				}
				else {
					tmp.dwDataOffset = lDiskOffset;
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
	MxU16 result = MMSYSERR_NOERROR;

	if (p_chunkInfo == NULL) {
		return MMIOERR_BASE;
	}

	if (dwFlags & MMIO_RWMODE) {
		if (pchBuffer) {
			size = (MxULong) (pchNext - pchBuffer) + lBufOffset - p_chunkInfo->dwDataOffset;
		}
		else {
			size = lDiskOffset - p_chunkInfo->dwDataOffset;
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
			if (pchBuffer && ofs >= lBufOffset && cchBuffer + lBufOffset > ofs) {
				memcpy(pchBuffer + (ofs - lBufOffset), (char*) &size, 4);
				dwFlags |= MMIO_DIRTY;
			}
			else {
				lDiskOffset = _llseek(M_FILE, ofs, SEEK_SET);

				if (lDiskOffset == ofs) {
					if (_lwrite(M_FILE, (char*) &size, 4) != 4) {
						lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
						result = MMIOERR_CANNOTWRITE;
					}
					else {
						lDiskOffset += 4; // TODO: compiler weirdness?
					}
				}
				else {
					lDiskOffset = _llseek(M_FILE, 0, SEEK_CUR);
					result = MMIOERR_CANNOTSEEK;
				}
			}
		}
	}

	// Seek past the end of the chunk (plus optional pad byte if size is odd)
	if (result == MMSYSERR_NOERROR &&
		Seek((p_chunkInfo->cksize & 1) + p_chunkInfo->cksize + p_chunkInfo->dwDataOffset, SEEK_SET) == -1) {
		result = MMIOERR_CANNOTSEEK;
	}

	return result;
}

// FUNCTION: BETA10 0x1015f28b
MxU16 MXIOINFO::CreateChunk(MMCKINFO* p_chunkInfo, MxU16 p_create)
{
	MxU16 result = MMSYSERR_NOERROR;

	if (p_chunkInfo == NULL) {
		return MMIOERR_BASE;
	}

	if (p_create == MMIO_CREATERIFF) {
		p_chunkInfo->ckid = FOURCC_RIFF;
	}
	if (p_create == MMIO_CREATELIST) {
		p_chunkInfo->ckid = FOURCC_LIST;
	}

	p_chunkInfo->dwDataOffset = Seek(0, SEEK_CUR);
	if (p_chunkInfo->dwDataOffset == -1) {
		result = MMIOERR_CANNOTSEEK;
	}
	else {
		p_chunkInfo->dwDataOffset += 8;
	}

	MxU32 size;
	if (p_chunkInfo->ckid == FOURCC_RIFF || p_chunkInfo->ckid == FOURCC_LIST) {
		size = 12;
	}
	else {
		size = 8;
	}

	if (Write(p_chunkInfo, size) != size) {
		result = MMIOERR_CANNOTWRITE;
	}

	p_chunkInfo->dwFlags = MMIO_DIRTY;
	return result;
}
