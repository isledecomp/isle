#include "mxmediamanager.h"

#include "decomp.h"
#include "mxautolocker.h"
#include "mxomni.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxMediaManager, 0x2c);
DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// FUNCTION: LEGO1 0x100b84c0
MxMediaManager::MxMediaManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100b8560
MxMediaManager::~MxMediaManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100b85d0
MxResult MxMediaManager::Init()
{
	this->m_presenters = NULL;
	this->m_thread = NULL;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b85e0
MxResult MxMediaManager::InitPresenters()
{
	MxAutoLocker lock(&this->m_criticalSection);

	this->m_presenters = new MxPresenterList;

	if (!this->m_presenters) {
		this->Destroy();
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b8710
void MxMediaManager::Destroy()
{
	MxAutoLocker lock(&this->m_criticalSection);

	if (this->m_presenters)
		delete this->m_presenters;

	Init();
}

// FUNCTION: LEGO1 0x100b8790
MxResult MxMediaManager::Tickle()
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxPresenter* presenter;
	MxPresenterListCursor cursor(this->m_presenters);

	while (cursor.Next(presenter))
		presenter->Tickle();

	cursor.Reset();

	while (cursor.Next(presenter))
		presenter->PutData();

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b88c0
void MxMediaManager::RegisterPresenter(MxPresenter& p_presenter)
{
	MxAutoLocker lock(&this->m_criticalSection);

	this->m_presenters->Append(&p_presenter);
}

// FUNCTION: LEGO1 0x100b8980
void MxMediaManager::UnregisterPresenter(MxPresenter& p_presenter)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxPresenterListCursor cursor(this->m_presenters);

	if (cursor.Find(&p_presenter))
		cursor.Detach();
}

// FUNCTION: LEGO1 0x100b8ac0
void MxMediaManager::StopPresenters()
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxPresenter* presenter;
	MxPresenterListCursor cursor(this->m_presenters);

	while (cursor.Next(presenter))
		presenter->EndAction();
}
