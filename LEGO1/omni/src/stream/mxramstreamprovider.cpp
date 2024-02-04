#include "mxramstreamprovider.h"

#include "decomp.h"
#include "mxdsbuffer.h"
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

	delete[] m_pBufferOfFileSize;
	m_pBufferOfFileSize = NULL;

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
		if (m_pFile->Open(0) != 0) {
			path = MxString(MxOmni::GetCD()) + p_resource->GetAtom().GetInternal() + ".si";
			m_pFile->SetFileName(path.GetData());

			if (m_pFile->Open(0) != 0) {
				goto done;
			}
		}

		m_fileSize = m_pFile->CalcFileSize();
		if (m_fileSize != 0) {
			m_bufferSize = m_pFile->GetBufferSize();
			m_pBufferOfFileSize = new MxU8[m_fileSize];
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

// FUNCTION: LEGO1 0x100d0d80
MxU32 ReadData(MxU8* p_buffer, MxU32 p_size)
{
	MxU32 id;
	MxU8* data = p_buffer;
	MxU8* end = p_buffer + p_size;
	MxU8* data2;

	if (p_buffer < end) {
		do {
			if (*MxDSChunk::IntoType(data) == FOURCC('M', 'x', 'O', 'b')) {
				data2 = data;
				data += 8;

				MxDSObject* obj = DeserializeDSObjectDispatch(&data, -1);
				id = obj->GetObjectId();
				delete obj;

				data = MxDSChunk::End(data2);
				while (data < end) {
					if (*MxDSChunk::IntoType(data) == FOURCC('M', 'x', 'C', 'h')) {
						MxU8* data3 = data;
						MxU32* psize = MxDSChunk::IntoLength(data);
						data += MxDSChunk::Size(*psize);

						if ((*MxDSChunk::IntoType(data2) == FOURCC('M', 'x', 'C', 'h')) &&
							(*MxStreamChunk::IntoFlags(data2) & MxDSChunk::c_split)) {
							if (*MxStreamChunk::IntoObjectId(data2) == *MxStreamChunk::IntoObjectId(data3) &&
								(*MxStreamChunk::IntoFlags(data3) & MxDSChunk::c_split) &&
								*MxStreamChunk::IntoTime(data2) == *MxStreamChunk::IntoTime(data3)) {
								MxDSBuffer::Append(data2, data3);
								continue;
							}
							else {
								*MxStreamChunk::IntoFlags(data2) &= ~MxDSChunk::c_split;
							}
						}

						data2 += MxDSChunk::Size(*MxDSChunk::IntoLength(data2));
						memcpy(data2, data3, MxDSChunk::Size(*psize));

						if (*MxStreamChunk::IntoObjectId(data2) == id &&
							(*MxStreamChunk::IntoFlags(data2) & MxDSChunk::c_end)) {
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
		} while (data < end);
	}

	*MxStreamChunk::IntoFlags(data2) &= ~MxDSChunk::c_split;
	return MxDSChunk::End(data2) - p_buffer;
}
