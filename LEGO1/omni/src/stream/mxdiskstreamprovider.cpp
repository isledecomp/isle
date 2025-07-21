#include "mxdiskstreamprovider.h"

#include "mxautolock.h"
#include "mxdiskstreamcontroller.h"
#include "mxdsbuffer.h"
#include "mxdsfile.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxramstreamprovider.h"
#include "mxstreamcontroller.h"
#include "mxstring.h"
#include "mxthread.h"

DECOMP_SIZE_ASSERT(MxDiskStreamProviderThread, 0x1c)
DECOMP_SIZE_ASSERT(MxDiskStreamProvider, 0x60);

// GLOBAL: LEGO1 0x10102878
MxU32 g_unk0x10102878 = 0;

// FUNCTION: LEGO1 0x100d0f30
MxResult MxDiskStreamProviderThread::Run()
{
	if (m_target) {
		((MxDiskStreamProvider*) m_target)->WaitForWorkToComplete();
	}
	MxThread::Run();
	// They should probably have writen "return MxThread::Run()" but they didn't.
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100d0f50
MxResult MxDiskStreamProviderThread::StartWithTarget(MxDiskStreamProvider* p_target)
{
	m_target = p_target;
	return Start(0x1000, 0);
}

// FUNCTION: LEGO1 0x100d0f70
MxDiskStreamProvider::MxDiskStreamProvider()
{
	m_pFile = NULL;
	m_remainingWork = FALSE;
	m_unk0x35 = FALSE;
}

// FUNCTION: LEGO1 0x100d1240
MxDiskStreamProvider::~MxDiskStreamProvider()
{
	MxDSObject* action;
	m_unk0x35 = FALSE;

	do {
		action = NULL;

		{
			AUTOLOCK(m_criticalSection);
			m_list.PopFront(action);
		}

		if (!action) {
			break;
		}

		if (((MxDSStreamingAction*) action)->GetUnknowna0()->GetWriteOffset() < 0x20000) {
			g_unk0x10102878--;
		}

		((MxDiskStreamController*) m_pLookup)->FUN_100c8670((MxDSStreamingAction*) action);
	} while (action);

	if (m_remainingWork) {
		m_remainingWork = FALSE;
		m_busySemaphore.Release(1);
		m_thread.Terminate();
	}

	if (m_pFile) {
		delete m_pFile;
	}

	m_pFile = NULL;
}

// FUNCTION: LEGO1 0x100d13d0
MxResult MxDiskStreamProvider::SetResourceToGet(MxStreamController* p_resource)
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

		m_remainingWork = TRUE;
		m_busySemaphore.Init(0, 100);

		if (m_thread.StartWithTarget(this) == SUCCESS && p_resource != NULL) {
			result = SUCCESS;
		}
	}

done:
	return result;
}

// FUNCTION: LEGO1 0x100d15e0
void MxDiskStreamProvider::VTable0x20(MxDSAction* p_action)
{
	MxDSObject* action;

	if (p_action->GetObjectId() == -1) {
		m_unk0x35 = FALSE;

		do {
			action = NULL;

			{
				AUTOLOCK(m_criticalSection);
				m_list.PopFront(action);
			}

			if (!action) {
				return;
			}

			if (((MxDSStreamingAction*) action)->GetUnknowna0()->GetWriteOffset() < 0x20000) {
				g_unk0x10102878--;
			}

			((MxDiskStreamController*) m_pLookup)->FUN_100c8670((MxDSStreamingAction*) action);
		} while (action);
	}
	else {
		do {
			{
				AUTOLOCK(m_criticalSection);
				action = (MxDSStreamingAction*) m_list.FindAndErase(p_action);
			}

			if (!action) {
				return;
			}

			if (((MxDSStreamingAction*) action)->GetUnknowna0()->GetWriteOffset() < 0x20000) {
				g_unk0x10102878--;
			}

			((MxDiskStreamController*) m_pLookup)->FUN_100c8670((MxDSStreamingAction*) action);
		} while (action);
	}
}

// FUNCTION: LEGO1 0x100d1750
// FUNCTION: BETA10 0x101632b8
MxResult MxDiskStreamProvider::WaitForWorkToComplete()
{
	while (m_remainingWork) {
		m_busySemaphore.Acquire(INFINITE);
		if (m_unk0x35) {
			PerformWork();
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100d1780
MxResult MxDiskStreamProvider::FUN_100d1780(MxDSStreamingAction* p_action)
{
	if (!m_remainingWork) {
		return FAILURE;
	}

	if (p_action->GetUnknown9c() > 0 && !p_action->GetUnknowna0()) {
		MxDSBuffer* buffer = new MxDSBuffer();

		if (!buffer) {
			return FAILURE;
		}

		if (buffer->AllocateBuffer(GetFileSize(), MxDSBuffer::e_allocate) != SUCCESS) {
			delete buffer;
			return FAILURE;
		}

		p_action->SetUnknowna0(buffer);
	}

	if (p_action->GetUnknowna0()->GetWriteOffset() < 0x20000) {
		g_unk0x10102878++;
	}

	{
		AUTOLOCK(m_criticalSection);
		m_list.PushBack(p_action);
	}

	m_unk0x35 = TRUE;
	m_busySemaphore.Release(1);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100d18f0
void MxDiskStreamProvider::PerformWork()
{
	MxDiskStreamController* controller = (MxDiskStreamController*) m_pLookup;
	MxDSObject* streamingAction = NULL;

	{
		AUTOLOCK(m_criticalSection);
		if (!m_list.empty()) {
			streamingAction = m_list.front();

			if (streamingAction && !FUN_100d1af0((MxDSStreamingAction*) streamingAction)) {
				m_thread.Sleep(500);
				m_busySemaphore.Release(1);
				return;
			}
		}
	}

	MxDSBuffer* buffer;

	{
		AUTOLOCK(m_criticalSection);

		if (!m_list.PopFront(streamingAction)) {
			goto done;
		}
	}

	if (((MxDSStreamingAction*) streamingAction)->GetUnknowna0()->GetWriteOffset() < 0x20000) {
		g_unk0x10102878--;
	}

	buffer = ((MxDSStreamingAction*) streamingAction)->GetUnknowna0();

	if (m_pFile->GetPosition() == ((MxDSStreamingAction*) streamingAction)->GetBufferOffset() ||
		m_pFile->Seek(((MxDSStreamingAction*) streamingAction)->GetBufferOffset(), SEEK_SET) == 0) {
		buffer->SetUnknown14(m_pFile->GetPosition());

		if (m_pFile->ReadToBuffer(buffer) == SUCCESS) {
			buffer->SetUnknown1c(m_pFile->GetPosition());

			if (((MxDSStreamingAction*) streamingAction)->GetUnknown9c() > 0) {
				FUN_100d1b20(((MxDSStreamingAction*) streamingAction));
			}
			else {
				if (m_pLookup == NULL || !((MxDiskStreamController*) m_pLookup)->GetUnk0xc4()) {
					controller->FUN_100c8670(((MxDSStreamingAction*) streamingAction));
				}
				else {
					controller->FUN_100c7f40(((MxDSStreamingAction*) streamingAction));
				}
			}

			streamingAction = NULL;
		}
	}

done:
	if (streamingAction) {
		controller->FUN_100c8670(((MxDSStreamingAction*) streamingAction));
	}

	m_thread.Sleep(0);
}

// FUNCTION: LEGO1 0x100d1af0
MxBool MxDiskStreamProvider::FUN_100d1af0(MxDSStreamingAction* p_action)
{
	if (p_action->GetUnknowna0()->GetWriteOffset() == 0x20000) {
		return g_unk0x10102878 == 0;
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100d1b20
// FUNCTION: BETA10 0x10163712
MxResult MxDiskStreamProvider::FUN_100d1b20(MxDSStreamingAction* p_action)
{
	MxDSBuffer* buffer = new MxDSBuffer();

	if (!buffer) {
		return FAILURE;
	}

	MxU32 size = (p_action->GetUnknowna4() ? p_action->GetUnknowna4()->GetWriteOffset() : 0) +
				 p_action->GetUnknowna0()->GetWriteOffset() - (p_action->GetUnknown94() - p_action->GetBufferOffset());

	if (buffer->AllocateBuffer(size, MxDSBuffer::e_allocate) != SUCCESS) {
		delete buffer;
		return FAILURE;
	}

	MxU8* data;

	if (p_action->GetUnknowna4()) {
		buffer->FUN_100c7090(p_action->GetUnknowna4());
		data = buffer->GetBuffer() + p_action->GetUnknowna4()->GetWriteOffset();

		memcpy(data, p_action->GetUnknowna0()->GetBuffer(), p_action->GetUnknowna0()->GetWriteOffset());

		delete p_action->GetUnknowna4();
	}
	else {
		data = buffer->GetBuffer();

		memcpy(
			data,
			p_action->GetUnknowna0()->GetBuffer() + (p_action->GetUnknown94() - p_action->GetBufferOffset()),
			size
		);
	}

	p_action->SetUnknowna4(buffer);

#define IntoType(p) ((MxU32*) (p))

	while (data) {
		if (*IntoType(data) != FOURCC('M', 'x', 'O', 'b') &&
			*MxStreamChunk::IntoTime(data) > p_action->GetUnknown9c()) {
			*IntoType(data) = FOURCC('p', 'a', 'd', ' ');

			// DECOMP: prefer order that matches retail versus beta
			*(MxU32*) (data + 4) = buffer->GetBuffer() + buffer->GetWriteOffset() - data - 8;
			memset(data + 8, 0, *(MxU32*) (data + 4));
			size = ReadData(buffer->GetBuffer(), buffer->GetWriteOffset());

			buffer = new MxDSBuffer();
			if (buffer == NULL || buffer->AllocateBuffer(size, MxDSBuffer::e_allocate) != SUCCESS) {
				delete buffer;
				return FAILURE;
			}

			memcpy(buffer->GetBuffer(), p_action->GetUnknowna4()->GetBuffer(), size);
			p_action->GetUnknowna4()->SetMode(MxDSBuffer::e_allocate);
			delete p_action->GetUnknowna4();

			buffer->SetMode(MxDSBuffer::e_unknown);
			p_action->SetUnknowna4(buffer);
			MxU32 unk0x14 = p_action->GetUnknowna0()->GetUnknown14();

			for (data = p_action->GetUnknowna0()->GetBuffer();
				 *MxStreamChunk::IntoTime(data) <= p_action->GetUnknown9c();
				 data = MxDSChunk::End(data)) {
				unk0x14 += MxDSChunk::Size(data);
			}

			p_action->SetUnknown94(unk0x14);
			p_action->SetBufferOffset(p_action->GetUnknowna0()->GetUnknown14());
			delete p_action->GetUnknowna0();
			p_action->ClearUnknowna0();
			((MxDiskStreamController*) m_pLookup)->FUN_100c7890(p_action);
			return SUCCESS;
		}

		data = buffer->FUN_100c6fa0(data);
	}

	p_action->SetUnknown94(GetFileSize() + p_action->GetBufferOffset());
	p_action->SetBufferOffset(GetFileSize() + p_action->GetBufferOffset());
	FUN_100d1780(p_action);
	return SUCCESS;

#undef IntoType
}

// FUNCTION: LEGO1 0x100d1e90
MxU32 MxDiskStreamProvider::GetFileSize()
{
	return m_pFile->GetBufferSize();
}

// FUNCTION: LEGO1 0x100d1ea0
MxS32 MxDiskStreamProvider::GetStreamBuffersNum()
{
	return m_pFile->GetStreamBuffersNum();
}

// FUNCTION: LEGO1 0x100d1eb0
MxU32 MxDiskStreamProvider::GetLengthInDWords()
{
	return m_pFile->GetLengthInDWords();
}

// FUNCTION: LEGO1 0x100d1ec0
MxU32* MxDiskStreamProvider::GetBufferForDWords()
{
	return m_pFile->GetBuffer();
}
