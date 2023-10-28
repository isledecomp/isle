#include "mxdiskstreamprovider.h"

#include "mxomni.h"
#include "mxstreamcontroller.h"
#include "mxstring.h"
#include "mxthread.h"

DECOMP_SIZE_ASSERT(MxDiskStreamProvider, 0x60);

// OFFSET: LEGO1 0x100d0f30
MxResult MxDiskStreamProviderThread::Run()
{
	if (m_target != NULL)
		m_target->WaitForWorkToComplete();
	MxThread::Run();
	// They should probably have writen "return MxThread::Run()" but they didn't.
	return SUCCESS;
}

// OFFSET: LEGO1 0x100d0f70
MxDiskStreamProvider::MxDiskStreamProvider()
{
	this->m_pFile = NULL;
	this->m_remainingWork = 0;
	this->m_unk35 = 0;
}

// OFFSET: LEGO1 0x100d1240
MxDiskStreamProvider::~MxDiskStreamProvider()
{
	// TODO
}

// Matching but with esi / edi swapped
// OFFSET: LEGO1 0x100d1750
MxResult MxDiskStreamProvider::WaitForWorkToComplete()
{
	while (m_remainingWork != 0) {
		m_busySemaphore.Wait(INFINITE);
		if (m_unk35 != 0)
			PerformWork();
	}
	return SUCCESS;
}

// OFFSET: LEGO1 0x100d1760 STUB
void MxDiskStreamProvider::PerformWork()
{
	// TODO
}

// OFFSET: LEGO1 0x100d13d0
MxResult MxDiskStreamProvider::SetResourceToGet(MxStreamController* p_resource)
{
	m_pLookup = p_resource;
	MxString path = MxString(MxOmni::GetHD()) + p_resource->GetAtom().GetInternal() + ".si";

	MxDSFile* file = new MxDSFile(path.GetData(), 0);
	m_pFile = file;
	if (file != NULL) {
		if (file->Open(0) != 0) {
			path = MxString(MxOmni::GetCD()) + p_resource->GetAtom().GetInternal() + ".si";
			file->SetFileName(path);
			if (file->Open(0) != 0) {
				return FAILURE;
			}
		}

		m_remainingWork = 1;
		MxResult success = m_busySemaphore.Init(0, 100);
		// m_thread.Start();

		if (success == SUCCESS && p_resource != NULL) {
			return SUCCESS;
		}
	}
	return FAILURE;
}

// OFFSET: LEGO1 0x100d1e90
MxU32 MxDiskStreamProvider::GetFileSize()
{
	return m_pFile->GetBufferSize();
}

// OFFSET: LEGO1 0x100d1ea0
MxU32 MxDiskStreamProvider::GetStreamBuffersNum()
{
	return m_pFile->GetStreamBuffersNum();
}

// OFFSET: LEGO1 0x100d15e0 STUB
void MxDiskStreamProvider::vtable0x20(undefined4 p_unknown1)
{
	// TODO
}

// OFFSET: LEGO1 0x100d1eb0
MxU32 MxDiskStreamProvider::GetLengthInDWords()
{
	return m_pFile->GetLengthInDWords();
}

// OFFSET: LEGO1 0x100d1ec0
MxU32* MxDiskStreamProvider::GetBufferForDWords()
{
	return m_pFile->GetBuffer();
}
