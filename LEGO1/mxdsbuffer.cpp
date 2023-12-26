#include "mxdsbuffer.h"

#include "mxdiskstreamcontroller.h"
#include "mxdschunk.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxstreamchunk.h"
#include "mxstreamcontroller.h"
#include "mxstreamer.h"

DECOMP_SIZE_ASSERT(MxDSBuffer, 0x34);

// FUNCTION: LEGO1 0x100c6470
MxDSBuffer::MxDSBuffer()
{
	m_refcount = 0;
	m_pBuffer = NULL;
	m_pIntoBuffer = NULL;
	m_pIntoBuffer2 = NULL;
	m_unk0x14 = 0;
	m_unk0x18 = 0;
	m_unk0x1c = 0;
	m_writeOffset = 0;
	m_bytesRemaining = 0;
	m_mode = MxDSBufferType_Preallocated;
	m_unk0x30 = 0;
}

// FUNCTION: LEGO1 0x100c6530
MxDSBuffer::~MxDSBuffer()
{
	if (m_pBuffer != NULL) {

		switch (m_mode) {
		case MxDSBufferType_Allocate:
		case MxDSBufferType_Unknown:
			delete[] m_pBuffer;
			break;

		case MxDSBufferType_Chunk: {
			MxStreamer* streamer = Streamer();
			switch (m_writeOffset / 1024) {
			case 0x40: {
				MxU32 a = streamer->GetSubclass1().GetSize() << 10;
				MxU32 bit = ((m_pBuffer - streamer->GetSubclass1().GetBuffer()) / a) & 0x1f;
				MxU32 index = (((m_pBuffer - streamer->GetSubclass1().GetBuffer()) / a) & 0xFFFFFFE7) >> 3;

				if (((((*(MxU32*) &streamer->GetSubclass1().GetUnk08Ref()[(index)])) & 1) << bit) != 0) {
					MxU32* ptr = (MxU32*) &streamer->GetSubclass1().GetUnk08Ref()[(index)];
					*ptr = *ptr ^ bit;
				}
				break;
			}
			case 0x80: {
				MxU32 a = streamer->GetSubclass2().GetSize() << 10;
				MxU32 bit = ((m_pBuffer - streamer->GetSubclass2().GetBuffer()) / a) & 0x1f;
				MxU32 index = (((m_pBuffer - streamer->GetSubclass2().GetBuffer()) / a) & 0xFFFFFFE7) >> 3;

				if (((((*(MxU32*) &streamer->GetSubclass2().GetUnk08Ref()[(index)])) & 1) << bit) != 0) {
					MxU32* ptr = (MxU32*) &streamer->GetSubclass2().GetUnk08Ref()[(index)];
					*ptr = *ptr ^ bit;
				}
				break;
			}
			}
		}
		}
	}

	m_unk0x14 = 0;
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x100c6640
MxResult MxDSBuffer::AllocateBuffer(MxU32 p_bufferSize, MxDSBufferType p_mode)
{
	MxResult result = FAILURE;

	switch (p_mode) {
	case MxDSBufferType_Allocate:
		m_pBuffer = new MxU8[p_bufferSize];
		break;

	case MxDSBufferType_Chunk: {
		MxStreamer* streamer = Streamer();

		switch (p_bufferSize / 1024) {
		case 0x40: {
			for (MxU32 i = 0; i < 22; i++) {
				if (((1 << (i & 0x1f)) & (*(MxU32*) &streamer->GetSubclass1().GetUnk08Ref()[(i & ~0x18u) >> 3])) == 0) {
					MxU32* ptr = (MxU32*) &streamer->GetSubclass1().GetUnk08Ref()[(i & 0xffffffe7) >> 3];

					*ptr = *ptr ^ 1 << (i & 0x1f);

					m_pBuffer =
						(MxU8*) (streamer->GetSubclass1().GetSize() * i * 0x400 + streamer->GetSubclass1().GetBuffer());
					goto done;
				}
			}

			m_pBuffer = NULL;
			break;
		}
		case 0x80: {
			for (MxU32 i = 0; i < 2; i++) {
				if (((1 << (i & 0x1f)) & (*(MxU32*) &streamer->GetSubclass2().GetUnk08Ref()[(i & ~0x18u) >> 3])) == 0) {
					MxU32* ptr = (MxU32*) &streamer->GetSubclass2().GetUnk08Ref()[(i & 0xffffffe7) >> 3];

					*ptr = *ptr ^ 1 << (i & 0x1f);

					m_pBuffer =
						(MxU8*) (streamer->GetSubclass2().GetSize() * i * 0x400 + streamer->GetSubclass2().GetBuffer());
					goto done;
				}
			}

			m_pBuffer = NULL;
			break;
		}
		default:
			m_pBuffer = NULL;
		}
	}
	}

done:
	m_pIntoBuffer = m_pBuffer;
	m_pIntoBuffer2 = m_pBuffer;

	if (m_pBuffer != NULL) {
		m_mode = p_mode;
		m_bytesRemaining = p_bufferSize;
		m_writeOffset = p_bufferSize;
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6780
MxResult MxDSBuffer::SetBufferPointer(MxU32* p_buffer, MxU32 p_size)
{
	m_pBuffer = (MxU8*) p_buffer;
	m_pIntoBuffer = (MxU8*) p_buffer;
	m_pIntoBuffer2 = (MxU8*) p_buffer;
	m_bytesRemaining = p_size;
	m_writeOffset = p_size;
	m_mode = MxDSBufferType_Preallocated;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c67b0
MxResult MxDSBuffer::FUN_100c67b0(
	MxStreamController* p_controller,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction
)
{
	MxResult result = FAILURE;

	m_unk0x30 = (MxDSStreamingAction*) p_controller->GetUnk0x3c().Find(p_action, FALSE);
	if (m_unk0x30 == NULL)
		return FAILURE;

	MxU8* data;
	while (data = (MxU8*) SkipToData()) {
		if (*p_streamingAction == NULL) {
			result = CreateObject(p_controller, (MxU32*) data, p_action, p_streamingAction);

			if (result == FAILURE)
				return result;
			// TODO: Not a MxResult value?
			if (result == 1)
				break;
		}
		else {
			MxDSBuffer* buffer = (*p_streamingAction)->GetUnknowna0();

			if (buffer->CalcBytesRemaining(data) != SUCCESS) {
				return result;
			}

			if (buffer->GetBytesRemaining() == 0) {
				buffer->SetUnk30(m_unk0x30);

				result = buffer->CreateObject(p_controller, (MxU32*) buffer->GetBuffer(), p_action, p_streamingAction);
				if (result != SUCCESS) {
					return result;
				}

				if (buffer->GetRefCount() != 0) {
					// Note: *p_streamingAction is always null in MxRamStreamProvider
					((MxDiskStreamController*) p_controller)->InsertToList74(buffer);
					(*p_streamingAction)->SetUnknowna0(NULL);
				}

				((MxDiskStreamController*) p_controller)->FUN_100c7cb0(*p_streamingAction);
				*p_streamingAction = NULL;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c68a0
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

	if (*p_data == FOURCC('M', 'x', 'O', 'b'))
		return StartPresenterFromAction(p_controller, p_action, (MxDSAction*) header);
	else if (*p_data == FOURCC('M', 'x', 'C', 'h')) {
		MxStreamChunk* chunk = (MxStreamChunk*) header;
		if (!m_unk0x30->HasId((chunk)->GetObjectId())) {
			delete header;
			return SUCCESS;
		}

		return ParseChunk(p_controller, p_data, p_action, p_streamingAction, chunk);
	}

	delete header;
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
MxResult MxDSBuffer::ParseChunk(
	MxStreamController* p_controller,
	MxU32* p_data,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction,
	MxStreamChunk* p_header
)
{
	MxResult result = SUCCESS;

	if ((m_unk0x30->GetFlags() & 4) == 0 || m_unk0x30->GetUnknowna4() == NULL || -1 < p_header->GetTime()) {
		MxLong& ptr = p_header->GetTimeRef();
		ptr = ptr + m_unk0x30->GetUnknowna8();

		if ((p_header->GetFlags() & 0x10) == 0) {
			if ((p_header->GetFlags() & 2) != 0) {
				if (m_unk0x30->HasId(p_header->GetObjectId())) {
					// this could be an inlined function
					if ((m_unk0x30->GetFlags() & 4) == 0 ||
						m_unk0x30->GetLoopCount() < 2 && m_unk0x30->GetDuration() != -1) {
						if (p_action->GetObjectId() == m_unk0x30->GetObjectId() &&
							p_controller->VTable0x30(p_action) == SUCCESS) {
							p_controller->GetProvider()->VTable0x20(p_action);
							result = 1;
						}
					}
					else {
						if (p_action->GetObjectId() == p_header->GetObjectId()) {
							MxU32 val = p_controller->GetProvider()->GetBufferForDWords()[m_unk0x30->GetObjectId()];
							m_unk0x30->SetUnknown94(val);
							m_unk0x30->SetBufferOffset((val / m_writeOffset) * m_writeOffset);
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
				}
			}

			if (p_header) {
				if (p_header->SendChunk(p_controller->GetSubscriberList(), TRUE, p_action->GetUnknown24()) != SUCCESS) {
					delete p_header;
				}
			}
		}
		else {
			MxDSBuffer* buffer = new MxDSBuffer();
			if (buffer) {
				if (buffer->AllocateBuffer(p_header->GetLength() + 8 + MxDSChunk::ReturnE(), MxDSBufferType_Allocate) ==
						SUCCESS &&
					CalcBytesRemaining((MxU8*) p_data) == SUCCESS) {
					MxDSStreamingAction* streamingAction = new MxDSStreamingAction((MxDSStreamingAction&) *p_action);
					*p_streamingAction = streamingAction;
					if (streamingAction) {
						MxU32* ptr2 = MxStreamChunk::ReturnPlus8Ptr((MxU32*) m_pBuffer);
						*ptr2 = *ptr2 & 0xffef;
						delete p_header;
						(*p_streamingAction)->SetUnknowna0(buffer);
						return SUCCESS;
					}
				}
				delete buffer;
			}
			delete p_header;
		}
	}
	else {
		delete p_header;
		result = SUCCESS;
	}
	return result;
}

// FUNCTION: LEGO1 0x100c6d00
MxCore* MxDSBuffer::ReadChunk(MxDSBuffer* p_buffer, MxU32* p_chunkData, MxU16 p_flags)
{
	// This function reads a chunk. If it is an object, this function returns an MxDSObject. If it is a chunk,
	// returns a MxDSChunk.
	MxCore* result = NULL;
	MxU8* dataStart = (MxU8*) p_chunkData + 8;

	switch (*p_chunkData) {
	case FOURCC('M', 'x', 'O', 'b'):
		result = DeserializeDSObjectDispatch(&dataStart, p_flags);
		break;
	case FOURCC('M', 'x', 'C', 'h'):
		result = new MxStreamChunk();
		if (result != NULL && ((MxStreamChunk*) result)->ReadChunk(p_buffer, (MxU8*) p_chunkData) != SUCCESS) {
			delete result;
			result = NULL;
		}
		return result;
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6df0
MxU8* MxDSBuffer::SkipToData()
{
	MxU8* result = NULL;

	if (m_pIntoBuffer != NULL) {
		do {
			MxU32* ptr = (MxU32*) m_pIntoBuffer;
			switch (*ptr) {
			case FOURCC('L', 'I', 'S', 'T'):
			case FOURCC('R', 'I', 'F', 'F'):
				m_pIntoBuffer = (MxU8*) (ptr + 3);
				break;
			case FOURCC('M', 'x', 'O', 'b'):
			case FOURCC('M', 'x', 'C', 'h'):
				result = m_pIntoBuffer;
				m_pIntoBuffer = (MxU8*) ((ptr[1] & 1) + ptr[1] + (MxU32) ptr);
				m_pIntoBuffer = (MxU8*) ((MxU32*) m_pIntoBuffer + 2);
				if (m_pBuffer + (m_writeOffset - 8) < m_pIntoBuffer) {
					m_pIntoBuffer2 = result;
					m_pIntoBuffer = NULL;
					return result;
				}
				goto done;
			case FOURCC('M', 'x', 'D', 'a'):
			case FOURCC('M', 'x', 'S', 't'):
				m_pIntoBuffer = (MxU8*) (ptr + 2);
				break;
			case FOURCC('M', 'x', 'H', 'd'):
				m_pIntoBuffer = (MxU8*) ((MxU32) ptr + ptr[1] + 8);
				break;
			default:
				m_pIntoBuffer = NULL;
				m_pIntoBuffer2 = NULL;
				return NULL;
			}
		} while (m_pIntoBuffer <= m_pBuffer + (m_writeOffset - 8));
	}
done:
	m_pIntoBuffer2 = result;
	return result;
}

// FUNCTION: LEGO1 0x100c6ec0
MxU8 MxDSBuffer::ReleaseRef(MxDSChunk*)
{
	if (m_refcount != 0) {
		m_refcount--;
	}
	return 0;
}

// FUNCTION: LEGO1 0x100c6ee0
void MxDSBuffer::AddRef(MxDSChunk* p_chunk)
{
	if (p_chunk) {
		m_refcount++;
	}
}

// FUNCTION: LEGO1 0x100c6ef0
MxResult MxDSBuffer::CalcBytesRemaining(MxU8* p_data)
{
	MxResult result = FAILURE;
	MxU8* ptr;
	MxU32 bytesRead;
	if (m_mode == MxDSBufferType_Allocate) {
		if (m_bytesRemaining != 0) {

			if (m_writeOffset == m_bytesRemaining) {
				bytesRead = (*(MxU32*) p_data) + 8;
				ptr = p_data;
			}
			else {
				ptr = &p_data[MxStreamChunk::ReturnE() + 8];
				bytesRead = (*(MxU32*) p_data) - MxStreamChunk::ReturnE();
			}

			if (bytesRead <= m_bytesRemaining) {
				memcpy(m_pBuffer + (m_writeOffset - m_bytesRemaining), ptr, bytesRead);
				if (m_writeOffset == m_bytesRemaining) {
					MxU8* buffer = m_pBuffer;
					buffer[1] = *MxStreamChunk::ReturnPlus18Ptr((MxU32*) buffer) + MxStreamChunk::ReturnE();
				}

				result = SUCCESS;
				m_bytesRemaining = m_bytesRemaining - bytesRead;
			}
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
