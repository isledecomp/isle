#include "mxramstreamprovider.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxRAMStreamProvider, 0x24);

// FUNCTION: LEGO1 0x100d0730
MxRAMStreamProvider::MxRAMStreamProvider()
{
	m_bufferSize = 0;
	m_fileSize = 0;
	m_pBufferOfFileSize = NULL;
	m_lengthInDWords = 0;
	m_bufferForDWords = NULL;
}

// FUNCTION: LEGO1 0x100d0930
MxU32 MxRAMStreamProvider::GetFileSize()
{
	return m_fileSize;
}

// FUNCTION: LEGO1 0x100d0940
MxU32 MxRAMStreamProvider::GetStreamBuffersNum()
{
	return 1;
}

// FUNCTION: LEGO1 0x100d0950
MxU32 MxRAMStreamProvider::GetLengthInDWords()
{
	return m_lengthInDWords;
}

// FUNCTION: LEGO1 0x100d0960
MxU32* MxRAMStreamProvider::GetBufferForDWords()
{
	return m_bufferForDWords;
}

// FUNCTION: LEGO1 0x100d0a50
MxRAMStreamProvider::~MxRAMStreamProvider()
{
	m_bufferSize = 0;
	m_fileSize = 0;

	free(m_pBufferOfFileSize);
	m_pBufferOfFileSize = NULL;

	m_lengthInDWords = 0;

	free(m_bufferForDWords);
	m_bufferForDWords = NULL;
}

// STUB: LEGO1 0x100d0ae0
MxResult MxRAMStreamProvider::SetResourceToGet(MxStreamController* p_resource)
{
	return FAILURE;
}
