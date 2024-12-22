#include "mxdsbuffer.h"

#include "mxdiskstreamcontroller.h"
#include "mxdschunk.h"
#include "mxdsstreamingaction.h"
#include "mxmisc.h"
#include "mxomni.h"
#include "mxstreamchunk.h"
#include "mxstreamcontroller.h"
#include "mxstreamer.h"
#include "mxstreamprovider.h"

DECOMP_SIZE_ASSERT(MxDSBuffer, 0x34);

// FUNCTION: LEGO1 0x100c6470
// FUNCTION: BETA10 0x10156f00
MxDSBuffer::MxDSBuffer()
{
	m_pBuffer = NULL;
	m_pIntoBuffer = NULL;
	m_pIntoBuffer2 = NULL;
	m_referenceCount = 0;
	m_unk0x14 = 0;
	m_unk0x18 = 0;
	m_unk0x1c = 0;
	m_writeOffset = 0;
	m_bytesRemaining = 0;
	m_mode = e_preallocated;
	m_unk0x30 = 0;
}

// FUNCTION: LEGO1 0x100c6530
// FUNCTION: BETA10 0x10156ff7
MxDSBuffer::~MxDSBuffer()
{
	assert(m_referenceCount == 0);

	if (m_pBuffer != NULL) {
		switch (m_mode) {
		case e_allocate:
		case e_unknown:
			delete[] m_pBuffer;
			break;

		case e_chunk:
			Streamer()->ReleaseMemoryBlock(m_pBuffer, m_writeOffset / 1024);
			break;

		case e_preallocated:
			break;
		}
	}

	m_unk0x14 = 0;
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x100c6640
// FUNCTION: BETA10 0x10157146
MxResult MxDSBuffer::AllocateBuffer(MxU32 p_bufferSize, Type p_mode)
{
	MxResult result = FAILURE;

	switch (p_mode) {
	case e_allocate:
		m_pBuffer = new MxU8[p_bufferSize];
		assert(m_pBuffer); // m_firstRiffChunk?
		break;

	case e_chunk:
		m_pBuffer = Streamer()->GetMemoryBlock(p_bufferSize / 1024);
		break;
	}

	m_pIntoBuffer = m_pBuffer;
	m_pIntoBuffer2 = m_pBuffer;

	if (m_pBuffer != NULL) {
		m_bytesRemaining = p_bufferSize;
		m_writeOffset = m_bytesRemaining;
		m_mode = p_mode;
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6780
MxResult MxDSBuffer::SetBufferPointer(MxU8* p_buffer, MxU32 p_size)
{
	m_pBuffer = p_buffer;
	m_pIntoBuffer = p_buffer;
	m_pIntoBuffer2 = p_buffer;
	m_bytesRemaining = p_size;
	m_writeOffset = p_size;
	m_mode = e_preallocated;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c67b0
// FUNCTION: BETA10 0x10157295
MxResult MxDSBuffer::FUN_100c67b0(
	MxStreamController* p_controller,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction
)
{
	MxResult result = FAILURE;
	MxU8* data = m_pBuffer;

	m_unk0x30 = (MxDSStreamingAction*) p_controller->GetUnk0x3c().Find(p_action);
	if (m_unk0x30 == NULL) {
		return FAILURE;
	}

	while ((data = (MxU8*) SkipToData())) {
		if (*p_streamingAction != NULL) {
			MxDSBuffer* buffer = (*p_streamingAction)->GetUnknowna0();

			if (buffer->CalcBytesRemaining(data)) {
				goto done;
			}

			if (buffer->GetBytesRemaining() == 0) {
				buffer->m_unk0x30 = m_unk0x30;

				result = buffer->CreateObject(p_controller, (MxU32*) buffer->GetBuffer(), p_action, p_streamingAction);
				if (result == SUCCESS) {
					if (buffer->HasRef()) {
						// Note: *p_streamingAction is always null in MxRamStreamProvider
						((MxDiskStreamController*) p_controller)->InsertToList74(buffer);
						(*p_streamingAction)->ClearUnknowna0();
					}

					((MxDiskStreamController*) p_controller)->FUN_100c7cb0(*p_streamingAction);
					*p_streamingAction = NULL;
				}
				else {
					goto done;
				}
			}
		}
		else {
			result = CreateObject(p_controller, (MxU32*) data, p_action, p_streamingAction);

			if (result == FAILURE) {
				goto done;
			}
			else if (result == 1) {
				// TODO: Not a MxResult value?
				break;
			}
		}
	}

	result = SUCCESS;
done:
	return result;
}

// FUNCTION: LEGO1 0x100c68a0
// FUNCTION: BETA10 0x10157450
MxResult MxDSBuffer::CreateObject(
	MxStreamController* p_controller,
	MxU32* p_data,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction
)
{
	if (p_data == NULL) {
		return FAILURE;
	}

	MxCore* header = ReadChunk(this, p_data, p_action->GetUnknown24());

	if (header == NULL) {
		return FAILURE;
	}

	if (*p_data == FOURCC('M', 'x', 'O', 'b')) {
		MxDSAction* action = (MxDSAction*) header;
		return StartPresenterFromAction(p_controller, p_action, action);
	}
	else if (*p_data == FOURCC('M', 'x', 'C', 'h')) {
		MxStreamChunk* chunk = (MxStreamChunk*) header;
		if (!m_unk0x30->HasId((chunk)->GetObjectId())) {
			delete header;
			return SUCCESS;
		}

		return ParseChunk(p_controller, p_data, p_action, p_streamingAction, chunk);
	}
	else {
		delete header;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100c6960
MxResult MxDSBuffer::StartPresenterFromAction(
	MxStreamController* p_controller,
	MxDSAction* p_action1,
	MxDSAction* p_objectheader
)
{
	if (!m_unk0x30->GetInternalAction()) {
		p_objectheader->SetAtomId(p_action1->GetAtomId());
		p_objectheader->SetUnknown28(p_action1->GetUnknown28());
		p_objectheader->SetUnknown84(p_action1->GetUnknown84());
		p_objectheader->SetOrigin(p_action1->GetOrigin());
		p_objectheader->SetUnknown90(p_action1->GetUnknown90());
		p_objectheader->MergeFrom(*p_action1);

		m_unk0x30->SetInternalAction(p_objectheader->Clone());

		p_controller->InsertActionToList54(p_objectheader);

		if (MxOmni::GetInstance()->CreatePresenter(p_controller, *p_objectheader) != SUCCESS) {
			return FAILURE;
		}

		m_unk0x30->SetLoopCount(p_objectheader->GetLoopCount());
		m_unk0x30->SetFlags(p_objectheader->GetFlags());
		m_unk0x30->SetDuration(p_objectheader->GetDuration());

		if (m_unk0x30->GetInternalAction() == NULL) {
			return FAILURE;
		}
	}
	else if (p_objectheader) {
		delete p_objectheader;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c6a50
// FUNCTION: BETA10 0x10157795
MxResult MxDSBuffer::ParseChunk(
	MxStreamController* p_controller,
	MxU32* p_data,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction,
	MxStreamChunk* p_header
)
{
	MxResult result = SUCCESS;

	if (m_unk0x30->GetFlags() & MxDSAction::c_bit3 && m_unk0x30->GetUnknowna8() && p_header->GetTime() < 0) {
		delete p_header;
		return SUCCESS;
	}

	p_header->SetTime(p_header->GetTime() + m_unk0x30->GetUnknowna8());

	if (p_header->GetChunkFlags() & DS_CHUNK_SPLIT) {
		MxU32 length = p_header->GetLength() + MxDSChunk::GetHeaderSize() + 8;
		MxDSBuffer* buffer = new MxDSBuffer();

		if (!buffer || buffer->AllocateBuffer(length, e_allocate) != SUCCESS ||
			buffer->CalcBytesRemaining((MxU8*) p_data) != SUCCESS ||
			(*p_streamingAction = new MxDSStreamingAction((MxDSStreamingAction&) *p_action)) == NULL) {
			delete buffer;
			delete p_header;
			return FAILURE;
		}

		MxU16* flags = MxStreamChunk::IntoFlags(buffer->GetBuffer());
		*flags = p_header->GetChunkFlags() & ~DS_CHUNK_SPLIT;

		delete p_header;
		(*p_streamingAction)->SetUnknowna0(buffer);
	}
	else {
		if (p_header->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
			if (m_unk0x30->HasId(p_header->GetObjectId())) {
				if (m_unk0x30->GetFlags() & MxDSAction::c_bit3 &&
					(m_unk0x30->GetLoopCount() > 1 || m_unk0x30->GetDuration() == -1)) {

					if (p_action->GetObjectId() == p_header->GetObjectId()) {
						MxU32 val = p_controller->GetProvider()->GetBufferForDWords()[m_unk0x30->GetObjectId()];

						m_unk0x30->SetUnknown94(val);
						m_unk0x30->SetBufferOffset(m_writeOffset * (val / m_writeOffset));

						MxNextActionDataStart* data =
							p_controller->FindNextActionDataStartFromStreamingAction(m_unk0x30);

						if (data) {
							data->SetData(m_unk0x30->GetBufferOffset());
						}

						m_unk0x30->FUN_100cd2d0();
					}

					delete p_header;
					p_header = NULL;
				}
				else {
					if (p_action->GetObjectId() == p_header->GetObjectId() &&
						p_controller->VTable0x30(p_action) == SUCCESS) {
						p_controller->GetProvider()->VTable0x20(p_action);
						result = 1;
					}
				}
			}
		}

		if (p_header) {
			if (p_header->SendChunk(p_controller->GetSubscriberList(), TRUE, p_action->GetUnknown24()) != SUCCESS) {
				delete p_header;
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6d00
// FUNCTION: BETA10 0x10157c94
MxCore* MxDSBuffer::ReadChunk(MxDSBuffer* p_buffer, MxU32* p_chunkData, MxU16 p_flags)
{
	// This function reads a chunk. If it is an object, this function returns an MxDSObject. If it is a chunk,
	// returns a MxDSChunk.
	MxCore* result = NULL;
	MxU8* dataStart = (MxU8*) p_chunkData + 8;

	switch (*p_chunkData) {
	case FOURCC('M', 'x', 'O', 'b'): {
		MxDSObject* obj = DeserializeDSObjectDispatch(dataStart, p_flags);
		result = obj;
		break;
	}
	case FOURCC('M', 'x', 'C', 'h'): {
		MxStreamChunk* chunk = new MxStreamChunk();
		if (chunk && chunk->ReadChunk(p_buffer, (MxU8*) p_chunkData) != SUCCESS) {
			delete chunk;
			chunk = NULL;
		}

		result = chunk;
		break;
	}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6df0
// FUNCTION: BETA10 0x10157e0a
MxU8* MxDSBuffer::SkipToData()
{
	MxU8* result = NULL;

	if (m_pIntoBuffer != NULL) {
		while (TRUE) {
			switch (*(MxU32*) m_pIntoBuffer) {
			case FOURCC('M', 'x', 'O', 'b'):
			case FOURCC('M', 'x', 'C', 'h'):
				result = m_pIntoBuffer;
				m_pIntoBuffer += (*(MxU32*) (m_pIntoBuffer + 4) & 1) + *(MxU32*) (m_pIntoBuffer + 4);
				m_pIntoBuffer += 8;

				if (m_pBuffer + m_writeOffset - 8 < m_pIntoBuffer) {
					m_pIntoBuffer = NULL;
				}

				goto done;
			case FOURCC('M', 'x', 'D', 'a'):
			case FOURCC('M', 'x', 'S', 't'):
				m_pIntoBuffer += 8;
				break;
			case FOURCC('M', 'x', 'H', 'd'):
				m_pIntoBuffer += *(MxU32*) (m_pIntoBuffer + 4) + 8;
				break;
			case FOURCC('L', 'I', 'S', 'T'):
			case FOURCC('R', 'I', 'F', 'F'):
				m_pIntoBuffer += 12;
				break;
			default:
				m_pIntoBuffer = NULL;
				result = NULL;
				goto done;
			}

			if (m_pIntoBuffer > m_pBuffer + m_writeOffset - 8) {
				m_pIntoBuffer = NULL;
				goto done;
			}
		}
	}
done:
	m_pIntoBuffer2 = result;
	return result;
}

// FUNCTION: LEGO1 0x100c6ec0
MxU8 MxDSBuffer::ReleaseRef(MxDSChunk*)
{
	if (m_referenceCount != 0) {
		m_referenceCount--;
	}
	return 0;
}

// FUNCTION: LEGO1 0x100c6ee0
void MxDSBuffer::AddRef(MxDSChunk* p_chunk)
{
	if (p_chunk) {
		m_referenceCount++;
	}
}

// FUNCTION: LEGO1 0x100c6ef0
// FUNCTION: BETA10 0x101580ad
MxResult MxDSBuffer::CalcBytesRemaining(MxU8* p_data)
{
	MxResult result = FAILURE;

	if (m_mode == e_allocate && m_bytesRemaining != 0) {
		MxU32 bytesRead;
		MxU8* ptr;

		if (m_writeOffset == m_bytesRemaining) {
			ptr = p_data;
			bytesRead = *(MxU32*) (p_data + 4) + 8;
		}
		else {
			ptr = p_data + MxStreamChunk::GetHeaderSize() + 8;
			bytesRead = (*(MxU32*) (p_data + 4)) - MxStreamChunk::GetHeaderSize();
		}

		if (bytesRead <= m_bytesRemaining) {
			memcpy(m_pBuffer + m_writeOffset - m_bytesRemaining, ptr, bytesRead);

			if (m_writeOffset == m_bytesRemaining) {
				*(MxU32*) (m_pBuffer + 4) = *MxStreamChunk::IntoLength(m_pBuffer) + MxStreamChunk::GetHeaderSize();
			}

			m_bytesRemaining -= bytesRead;
			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6f80
void MxDSBuffer::FUN_100c6f80(MxU32 p_writeOffset)
{
	if (p_writeOffset < m_writeOffset) {
		m_pIntoBuffer2 = m_pBuffer + p_writeOffset;
		m_pIntoBuffer = m_pBuffer + p_writeOffset;
	}
}

// FUNCTION: LEGO1 0x100c6fa0
MxU8* MxDSBuffer::FUN_100c6fa0(MxU8* p_data)
{
	MxU8* current = p_data ? p_data : m_pBuffer;
	MxU8* end = m_writeOffset + m_pBuffer - 8;

	while (current <= end) {
		switch (*((MxU32*) current)) {
		case FOURCC('L', 'I', 'S', 'T'):
		case FOURCC('R', 'I', 'F', 'F'):
			current += 12;
			break;
		case FOURCC('M', 'x', 'D', 'a'):
		case FOURCC('M', 'x', 'S', 't'):
			current += 8;
			break;
		case FOURCC('M', 'x', 'O', 'b'):
		case FOURCC('M', 'x', 'C', 'h'):
			if (current != p_data) {
				return current;
			}
			current = ((MxU32) current & 1) + current;
			current += 8;
			break;
		case FOURCC('M', 'x', 'H', 'd'):
			current += (((MxU32*) current)[1] + 8);
			break;
		default:
			return NULL;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100c7090
MxResult MxDSBuffer::FUN_100c7090(MxDSBuffer* p_buf)
{
	MxResult result = FAILURE;

	if (m_writeOffset >= p_buf->m_writeOffset) {
		memcpy(m_pBuffer, p_buf->m_pBuffer, p_buf->m_writeOffset);
		result = SUCCESS;
	}

	m_unk0x1c = p_buf->m_unk0x1c;
	return result;
}

// FUNCTION: LEGO1 0x100c70d0
MxResult MxDSBuffer::Append(MxU8* p_buffer1, MxU8* p_buffer2)
{
	if (p_buffer1 && p_buffer2) {
		MxU32 size = ((MxU32*) p_buffer2)[1] - MxDSChunk::GetHeaderSize();
		memcpy(p_buffer1 + ((MxU32*) p_buffer1)[1] + 8, p_buffer2 + MxDSChunk::GetHeaderSize() + 8, size);
		((MxU32*) p_buffer1)[1] += size;
		return SUCCESS;
	}
	return FAILURE;
}
