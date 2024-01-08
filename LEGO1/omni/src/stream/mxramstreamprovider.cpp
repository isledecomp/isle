#include "mxramstreamprovider.h"

#include "decomp.h"
#include "mxomni.h"
#include "mxstreamcontroller.h"

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
MxS32 MxRAMStreamProvider::GetStreamBuffersNum()
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

// FUNCTION: LEGO1 0x100d0ae0
MxResult MxRAMStreamProvider::SetResourceToGet(MxStreamController* p_resource)
{
	MxResult result = FAILURE;
	MxString path;
	m_pLookup = p_resource;

	path = (MxString(MxOmni::GetHD()) + p_resource->GetAtom().GetInternal() + ".si");

	m_pFile = new MxDSFile(path.GetData(), 0);
	if (m_pFile != NULL) {
		if (m_pFile->Open(0) != 0) {
			path = MxString(MxOmni::GetCD()) + p_resource->GetAtom().GetInternal() + ".si";
			m_pFile->SetFileName(path.GetData());

			if (m_pFile->Open(0) != 0)
				goto done;
		}

		m_fileSize = m_pFile->CalcFileSize();
		if (m_fileSize != 0) {
			m_bufferSize = m_pFile->GetBufferSize();
			m_pBufferOfFileSize = (MxU32*) new MxU8[m_fileSize];
			if (m_pBufferOfFileSize != NULL &&
				m_pFile->Read((unsigned char*) m_pBufferOfFileSize, m_fileSize) == SUCCESS) {
				m_lengthInDWords = m_pFile->GetLengthInDWords();
				m_bufferForDWords = new MxU32[m_lengthInDWords];

				if (m_bufferForDWords != NULL) {
					memcpy(m_bufferForDWords, m_pFile->GetBuffer(), m_lengthInDWords * sizeof(MxU32));
					result = SUCCESS;
				}
			}
		}
	}

done:
	delete m_pFile;
	m_pFile = NULL;
	return result;
}
