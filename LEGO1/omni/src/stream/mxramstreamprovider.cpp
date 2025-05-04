#include "mxramstreamprovider.h"

#include "decomp.h"
#include "mxdsbuffer.h"
#include "mxdsfile.h"
#include "mxomni.h"
#include "mxstreamcontroller.h"

DECOMP_SIZE_ASSERT(MxStreamProvider, 0x10)
DECOMP_SIZE_ASSERT(MxRAMStreamProvider, 0x24)

// FUNCTION: LEGO1 0x100d0730
MxRAMStreamProvider::MxRAMStreamProvider()
{
	m_bufferSize = 0;
	m_fileSize = 0;
	m_pContentsOfFile = NULL;
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

	delete[] m_pContentsOfFile;
	m_pContentsOfFile = NULL;

	m_lengthInDWords = 0;

	delete[] m_bufferForDWords;
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
		if (m_pFile->Open(OF_READ) != 0) {
			path = MxString(MxOmni::GetCD()) + p_resource->GetAtom().GetInternal() + ".si";
			m_pFile->SetFileName(path.GetData());

			if (m_pFile->Open(OF_READ) != 0) {
				goto done;
			}
		}

		m_fileSize = m_pFile->CalcFileSize();
		if (m_fileSize != 0) {
			m_bufferSize = m_pFile->GetBufferSize();
			m_pContentsOfFile = new MxU8[m_fileSize];
			if (m_pContentsOfFile != NULL &&
				m_pFile->Read((unsigned char*) m_pContentsOfFile, m_fileSize) == SUCCESS) {
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

// FUNCTION: LEGO1 0x100d0d80
// FUNCTION: BETA10 0x1016492f
MxU32 ReadData(MxU8* p_buffer, MxU32 p_size)
{
	MxU32 id;
	MxU8* data = p_buffer;
	MxU8* startOfChunk;

#define IntoType(p) ((MxU32*) (p))

	while (data < p_buffer + p_size) {
		if (*IntoType(data) == FOURCC('M', 'x', 'O', 'b')) {
			startOfChunk = data;
			data = startOfChunk + 8;

			MxDSObject* obj = DeserializeDSObjectDispatch(data, -1);
			id = obj->GetObjectId();
			delete obj;

			data = MxDSChunk::End(startOfChunk);
			while (data < p_buffer + p_size) {
				if (*IntoType(data) == FOURCC('M', 'x', 'C', 'h')) {
					MxU8* startOfSubChunk = data;
					data = MxDSChunk::End(startOfSubChunk);

					if ((*IntoType(startOfChunk) == FOURCC('M', 'x', 'C', 'h')) &&
						(*MxStreamChunk::IntoFlags(startOfChunk) & DS_CHUNK_SPLIT)) {
						if (*MxStreamChunk::IntoObjectId(startOfChunk) == *MxStreamChunk::IntoObjectId(startOfSubChunk) &&
							(*MxStreamChunk::IntoFlags(startOfSubChunk) & DS_CHUNK_SPLIT) &&
							*MxStreamChunk::IntoTime(startOfChunk) == *MxStreamChunk::IntoTime(startOfSubChunk)) {
							MxDSBuffer::Append(startOfChunk, startOfSubChunk);
							continue;
						}
						else {
							*MxStreamChunk::IntoFlags(startOfChunk) &= ~DS_CHUNK_SPLIT;
						}
					}

					startOfChunk = MxDSChunk::End(startOfChunk);
					memcpy(startOfChunk, startOfSubChunk, MxDSChunk::Size(startOfSubChunk));

					if (*MxStreamChunk::IntoObjectId(startOfChunk) == id &&
						(*MxStreamChunk::IntoFlags(startOfChunk) & DS_CHUNK_END_OF_STREAM)) {
						break;
					}
				}
				else {
					data++;
				}
			}
		}
		else {
			data++;
		}
	}

	*MxStreamChunk::IntoFlags(startOfChunk) &= ~DS_CHUNK_SPLIT;
	return MxDSChunk::Size(startOfChunk) + (MxU32) (startOfChunk - p_buffer);

#undef IntoType
}
