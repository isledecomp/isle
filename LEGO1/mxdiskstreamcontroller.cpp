#include "mxdiskstreamcontroller.h"

#include "mxautolocker.h"
#include "mxdiskstreamprovider.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxDiskStreamController, 0xc8);

// FUNCTION: LEGO1 0x100c7120
MxDiskStreamController::MxDiskStreamController()
{
	m_unk0x8c = 0;
}

// STUB: LEGO1 0x100c7530
MxDiskStreamController::~MxDiskStreamController()
{
	// TODO
}

// FUNCTION: LEGO1 0x100c7790
MxResult MxDiskStreamController::Open(const char* p_filename)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxResult result = MxStreamController::Open(p_filename);

	if (result == SUCCESS) {
		m_provider = new MxDiskStreamProvider();
		if (m_provider == NULL) {
			result = FAILURE;
		}
		else {
			result = m_provider->SetResourceToGet(this);
			if (result != SUCCESS) {
				delete m_provider;
				m_provider = NULL;
			}
			else {
				TickleManager()->RegisterClient(this, 10);
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c7880
MxResult MxDiskStreamController::VTable0x18(undefined4, undefined4)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c7960
MxResult MxDiskStreamController::VTable0x34(undefined4)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c7980
void MxDiskStreamController::FUN_100c7980()
{
	MxDSBuffer* buffer;
	MxDSStreamingAction* action = NULL;
	MxAutoLocker lock(&this->m_criticalSection);

	if (m_unk0x3c.size() != 0 || m_provider->GetStreamBuffersNum() > m_unk0x8c) {
		buffer = new MxDSBuffer();
		if (buffer->AllocateBuffer(m_provider->GetFileSize(), MxDSBufferType_Chunk) == SUCCESS) {
			action = VTable0x28();
			if (action) {
				action->SetUnknowna0(buffer);
				m_unk0x8c++;
			}
			else {
				return;
			}
		}
		else {
			delete buffer;
			return;
		}
	}

	if (action) {
		((MxDiskStreamProvider*) m_provider)->FUN_100d1780(action);
	}
}

// STUB: LEGO1 0x100c7ac0
MxDSStreamingAction* MxDiskStreamController::VTable0x28()
{
	// TODO
	return NULL;
}

// FUNCTION: LEGO1 0x100c7c00
MxResult MxDiskStreamController::VTable0x30(MxDSAction* p_action)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxResult result = MxStreamController::VTable0x30(p_action);

	MxDSStreamingAction* item;
	while(TRUE)
	{
		item = (MxDSStreamingAction*)m_list0x90.Find(p_action, TRUE);
		if (item == NULL)
		{
			break;
		}
		FUN_100c7cb0(item);
	}

	while(TRUE)
	{
		item = (MxDSStreamingAction*)m_list0x64.Find(p_action, TRUE);
		if (item == NULL)
		{
			break;
		}
		FUN_100c7cb0(item);
	}

	return result;
}

// FUNCTION: LEGO1 0x100c7cb0
void MxDiskStreamController::FUN_100c7cb0(MxDSStreamingAction* p_action)
{
	if (p_action->GetUnknowna0()) {
		FUN_100c7ce0(p_action->GetUnknowna0());
	}
	p_action->SetUnknowna0(NULL);
	delete p_action;
}

// FUNCTION: LEGO1 0x100c7ce0
void MxDiskStreamController::FUN_100c7ce0(MxDSBuffer* p_buffer)
{
	switch (p_buffer->GetMode()) {
	case MxDSBufferType_Chunk:
		m_unk0x8c--;
	case MxDSBufferType_Allocate:
	case MxDSBufferType_Unknown:
		delete p_buffer;
		break;
	}
}

// STUB: LEGO1 0x100c7d10
MxResult MxDiskStreamController::FUN_100c7d10()
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c7f40
void MxDiskStreamController::FUN_100c7f40(MxDSStreamingAction* p_streamingaction)
{
	MxAutoLocker lock(&this->m_criticalSection);
	if (p_streamingaction) {
		m_list0x64.push_back(p_streamingaction);
	}
}

// FUNCTION: LEGO1 0x100c7ff0
MxResult MxDiskStreamController::VTable0x20(MxDSAction* p_action)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxDSStreamingAction* entry =
		(MxDSStreamingAction*) m_list0x80.Find(p_action, FALSE); // TODO: is this a seperate class?

	if (entry) {
		MxDSStreamingAction* action = new MxDSStreamingAction(*p_action, 0);
		action->SetUnknown28(entry->GetUnknown28());
		action->SetUnknown84(entry->GetUnknown84());
		action->SetOrigin(entry->GetOrigin());
		action->SetUnknowna0(entry->GetUnknowna4());

		FUN_100c7f40(action);

		if (VTable0x2c(p_action, entry->GetUnknown94()) != SUCCESS)
			return FAILURE;
	}
	else if (MxStreamController::VTable0x20(p_action) != SUCCESS)
		return FAILURE;

	m_unk0x70 = 1;
	m_unk0xc4 = 1;
	return SUCCESS;
}

// STUB: LEGO1 0x100c8160
MxResult MxDiskStreamController::VTable0x24(MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c84a0
void MxDiskStreamController::InsertToList74(MxDSBuffer* p_buffer)
{
	MxAutoLocker lock(&this->m_criticalSection);
	m_list0x74.push_back(p_buffer);
}

// STUB: LEGO1 0x100c8540
void MxDiskStreamController::FUN_100c8540()
{
	// TODO
}

// FUNCTION: LEGO1 0x100c8640
MxResult MxDiskStreamController::Tickle()
{
	if (m_unk0xc4) {
		FUN_100c7d10();
	}

	FUN_100c8540();
	FUN_100c8720();

	if (m_unk0x70) {
		FUN_100c7980();
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c8720
void MxDiskStreamController::FUN_100c8720()
{
	MxAutoLocker lock(&this->m_critical9c);

	MxDSStreamingAction* action;
	while (m_list0xb8.size() != 0) {
		action = (MxDSStreamingAction*) m_list0xb8.front();
		m_list0xb8.pop_front();

		FUN_100c7cb0(action);
	}
}
