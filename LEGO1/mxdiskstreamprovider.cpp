#include "mxdiskstreamprovider.h"

#include "mxomni.h"
#include "mxstreamcontroller.h"
#include "mxstring.h"
#include "mxthread.h"

DECOMP_SIZE_ASSERT(MxDiskStreamProvider, 0x60);

// OFFSET: LEGO1 0x100d0f30
MxResult MxDiskStreamProviderThread::Run()
{
	if (m_target)
		((MxDiskStreamProvider*) m_target)->WaitForWorkToComplete();
	MxThread::Run();
	// They should probably have writen "return MxThread::Run()" but they didn't.
	return SUCCESS;
}

// OFFSET: LEGO1 0x100d0f50
MxResult MxDiskStreamProviderThread::StartWithTarget(MxDiskStreamProvider* p_target)
{
	m_target = p_target;
	return Start(0x1000, 0);
}

// OFFSET: LEGO1 0x100d0f70
MxDiskStreamProvider::MxDiskStreamProvider()
{
	this->m_pFile = NULL;
	this->m_remainingWork = 0;
	this->m_unk35 = 0;
}

// OFFSET: LEGO1 0x100d1240 STUB
MxDiskStreamProvider::~MxDiskStreamProvider()
{
	// TODO
}

// OFFSET: LEGO1 0x100d13d0
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
		MxResult success = m_busySemaphore.Init(0, 100);
		m_thread.StartWithTarget(this);

		if (success == SUCCESS && p_resource != NULL) {
			result = SUCCESS;
		}
	}

done:
	return result;
}

// OFFSET: LEGO1 0x100d15e0 STUB
void MxDiskStreamProvider::vtable0x20(undefined4 p_unknown1)
{
	// TODO
}

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

// OFFSET: LEGO1 0x100d18f0 STUB
void MxDiskStreamProvider::PerformWork()
{
	// TODO
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
