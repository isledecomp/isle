#include "mxdiskstreamprovider.h"

#include "mxautolocker.h"
#include "mxdiskstreamcontroller.h"
#include "mxdsbuffer.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxstreamcontroller.h"
#include "mxstring.h"
#include "mxthread.h"

DECOMP_SIZE_ASSERT(MxDiskStreamProvider, 0x60);

// GLOBAL: LEGO1 0x10102878
MxU32 g_unk0x10102878 = 0;

// FUNCTION: LEGO1 0x100d0f30
MxResult MxDiskStreamProviderThread::Run()
{
	if (m_target)
		((MxDiskStreamProvider*) m_target)->WaitForWorkToComplete();
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
	this->m_pFile = NULL;
	this->m_remainingWork = 0;
	this->m_unk0x35 = 0;
}

// STUB: LEGO1 0x100d1240
MxDiskStreamProvider::~MxDiskStreamProvider()
{
	// TODO
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
		if (m_pFile->Open(0) != 0) {
			path = MxString(MxOmni::GetCD()) + p_resource->GetAtom().GetInternal() + ".si";
			m_pFile->SetFileName(path.GetData());

			if (m_pFile->Open(0) != 0)
				goto done;
		}

		m_remainingWork = 1;
		m_busySemaphore.Init(0, 100);

		if (m_thread.StartWithTarget(this) == SUCCESS && p_resource != NULL) {
			result = SUCCESS;
		}
	}

done:
	return result;
}

// STUB: LEGO1 0x100d15e0
void MxDiskStreamProvider::VTable0x20(MxDSAction* p_action)
{
	OutputDebugStringA("MxDiskStreamProvider::VTable0x20");
	// TODO
}

// FUNCTION: LEGO1 0x100d1750
MxResult MxDiskStreamProvider::WaitForWorkToComplete()
{
	OutputDebugStringA("WaitForWorkToComplete\n");
	while (m_remainingWork != 0) {
		m_busySemaphore.Wait(INFINITE);
		if (m_unk0x35 != 0)
			PerformWork();
	}
	OutputDebugStringA("Work is completed\n");
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100d1780
MxResult MxDiskStreamProvider::FUN_100d1780(MxDSStreamingAction* p_action)
{
	if (m_remainingWork != 0) {
		if (p_action->GetUnknown94() > 0 && !p_action->GetUnknowna0()) {
			MxDSBuffer* buffer = new MxDSBuffer();
			if (buffer) {
				if (buffer->AllocateBuffer(GetFileSize(), MxDSBufferType_Allocate) == SUCCESS) {
					p_action->SetUnknowna0(buffer);
				}
				else {
					delete buffer;
					return FAILURE;
				}
			}
		}

		if (p_action->GetUnknowna0()->GetWriteOffset() < 0x20000) {
			g_unk0x10102878++;
		}

		{
			MxAutoLocker lock(&m_criticalSection);
			m_list.push_back(p_action);
		}

		m_unk0x35 = 1;
		m_busySemaphore.Release(1);
		return SUCCESS;
	}
	return FAILURE;
}

// FUNCTION: LEGO1 0x100d18f0
void MxDiskStreamProvider::PerformWork()
{
	MxDSStreamingAction* action;
	{
		MxAutoLocker lock(&m_criticalSection);
		if (m_list.size() != 0 && !FUN_100d1af0((MxDSStreamingAction*)m_list.front())) {
			MxThread::Sleep(500);
			m_busySemaphore.Release(1);
			return;
		}
	}

	{
		MxAutoLocker lock(&m_criticalSection);
		if (m_list.size() != 0) {
			action = (MxDSStreamingAction*)m_list.front();
			m_list.pop_front();

			// TODO delete lock here (could be an line function)
			if (action->GetUnknowna0()->GetWriteOffset() < 0x20000) {
				g_unk0x10102878--;
			}

			MxDSBuffer* buffer = action->GetUnknowna0();
			if (m_pFile->GetPosition() == action->GetUnknowna0()->GetWriteOffset() ||
				m_pFile->Seek(action->GetBufferOffset(), 0) == 0) {
				buffer->SetUnknown14(m_pFile->GetPosition());
				if (m_pFile->ReadToBuffer(buffer) == SUCCESS) {
					buffer->SetUnknown1c(m_pFile->GetPosition());
					if (action->GetUnknown9c() < 1) {
						if (m_pLookup == NULL || !((MxDiskStreamController*) m_pLookup)->GetUnk0xc4()) {
							((MxDiskStreamController*) m_pLookup)->FUN_100c8670(action);
						}
						else {
							((MxDiskStreamController*) m_pLookup)->FUN_100c7f40(action);
						}
					}
					else {
						FUN_100d1b20(action);
					}

					action = NULL;
				}
			}
		}
	}

	if (action)
	{
		((MxDiskStreamController*) m_pLookup)->FUN_100c8670(action);
	}
	MxThread::Sleep(0);
}

// FUNCTION: LEGO1 0x100d1af0
MxBool MxDiskStreamProvider::FUN_100d1af0(MxDSStreamingAction* p_action)
{
	if (p_action->GetUnknowna0()->GetWriteOffset() == 0x20000) {
		return g_unk0x10102878 == 0;
	}

	return TRUE;
}

// STUB: LEGO1 0x100d1b20
MxResult MxDiskStreamProvider::FUN_100d1b20(MxDSStreamingAction* p_action)
{
	OutputDebugString("MxDiskStreamProvider::FUN_100d1b20");
	return FAILURE;
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
