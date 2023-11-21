#include "mxdsfile.h"

#include <stdio.h>

#define SI_MAJOR_VERSION 2
#define SI_MINOR_VERSION 2

// OFFSET: LEGO1 0x100bfed0
MxDSFile::~MxDSFile()
{
	Close();
}

// OFFSET: LEGO1 0x100cc4b0
MxDSFile::MxDSFile(const char* filename, MxULong skipReadingChunks)
{
	m_filename = filename;
	m_skipReadingChunks = skipReadingChunks;
}

// OFFSET: LEGO1 0x100cc590
MxLong MxDSFile::Open(MxULong uStyle)
{
	MXIOINFO& io = m_io;
	MxLong longResult = 1;
	memset(&io, 0, sizeof(MXIOINFO));

	if (io.Open(m_filename.GetData(), uStyle) != 0) {
		return -1;
	}

	io.SetBuffer(NULL, 0, 0);
	m_position = 0;

	if (m_skipReadingChunks == 0) {
		longResult = ReadChunks();
	}

	if (longResult != 0) {
		Close(); // vtable + 0x18
	}
	else {
		Seek(0, 0); // vtable + 0x24
	}

	return longResult;
}

// OFFSET: LEGO1 0x100cc620
MxLong MxDSFile::ReadChunks()
{
	_MMCKINFO topChunk;
	_MMCKINFO childChunk;
	char tempBuffer[80];

	topChunk.fccType = FOURCC('O', 'M', 'N', 'I');
	if (m_io.Descend(&topChunk, NULL, MMIO_FINDRIFF) != 0) {
		return -1;
	}
	childChunk.ckid = FOURCC('M', 'x', 'H', 'd');
	if (m_io.Descend(&childChunk, &topChunk, 0) != 0) {
		return -1;
	}

	m_io.Read(&m_header, 0xc);
	if ((m_header.majorVersion == SI_MAJOR_VERSION) && (m_header.minorVersion == SI_MINOR_VERSION)) {
		childChunk.ckid = FOURCC('M', 'x', 'O', 'f');
		if (m_io.Descend(&childChunk, &topChunk, 0) != 0) {
			return -1;
		}
		MxULong* pLengthInDWords = &m_lengthInDWords;
		m_io.Read(pLengthInDWords, 4);
		m_pBuffer = new MxU32[*pLengthInDWords];
		m_io.Read(m_pBuffer, *pLengthInDWords * 4);
		return 0;
	}
	else {
		sprintf(tempBuffer, "Wrong SI file version. %d.%d expected.", SI_MAJOR_VERSION, SI_MINOR_VERSION);
		MessageBoxA(NULL, tempBuffer, NULL, MB_ICONERROR);
		return -1;
	}
}

// OFFSET: LEGO1 0x100cc740
MxLong MxDSFile::Close()
{
	m_io.Close(0);
	m_position = -1;
	memset(&m_header, 0, sizeof(m_header));
	if (m_lengthInDWords != 0) {
		m_lengthInDWords = 0;
		delete[] m_pBuffer;
		m_pBuffer = NULL;
	}
	return 0;
}

// OFFSET: LEGO1 0x100cc780
MxResult MxDSFile::Read(unsigned char* p_buf, MxULong p_nbytes)
{
	if (m_io.Read(p_buf, p_nbytes) != p_nbytes)
		return FAILURE;

	m_position += p_nbytes;
	return SUCCESS;
}

// OFFSET: LEGO1 0x100cc7b0
MxLong MxDSFile::Seek(MxLong lOffset, int iOrigin)
{
	return (m_position = m_io.Seek(lOffset, iOrigin)) == -1 ? -1 : 0;
}

// OFFSET: LEGO1 0x100cc7e0
MxULong MxDSFile::GetBufferSize()
{
	return m_header.bufferSize;
}

// OFFSET: LEGO1 0x100cc7f0
MxULong MxDSFile::GetStreamBuffersNum()
{
	return m_header.streamBuffersNum;
}
