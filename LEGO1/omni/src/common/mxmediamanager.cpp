#include "mxmediamanager.h"

#include "decomp.h"
#include "mxautolock.h"
#include "mxomni.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxMediaManager, 0x2c);
DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// FUNCTION: LEGO1 0x100b84c0
// FUNCTION: BETA10 0x10144680
MxMediaManager::MxMediaManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100b8560
// FUNCTION: BETA10 0x10144712
MxMediaManager::~MxMediaManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100b85d0
// FUNCTION: BETA10 0x1014479b
MxResult MxMediaManager::Init()
{
	this->m_presenters = NULL;
	this->m_thread = NULL;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b85e0
// FUNCTION: BETA10 0x101447c5
MxResult MxMediaManager::Create()
{
	AUTOLOCK(m_criticalSection);

	this->m_presenters = new MxPresenterList;

	if (!this->m_presenters) {
		this->Destroy();
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b8710
// FUNCTION: BETA10 0x101448e4
void MxMediaManager::Destroy()
{
	AUTOLOCK(m_criticalSection);

	if (this->m_presenters) {
		delete this->m_presenters;
	}

	Init();
}

// FUNCTION: LEGO1 0x100b8790
// FUNCTION: BETA10 0x10144993
MxResult MxMediaManager::Tickle()
{
	AUTOLOCK(m_criticalSection);
	MxPresenter* presenter;
	MxPresenterListCursor cursor(this->m_presenters);

	while (cursor.Next(presenter)) {
		presenter->Tickle();
	}

	cursor.Reset();

	while (cursor.Next(presenter)) {
		presenter->PutData();
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b88c0
// FUNCTION: BETA10 0x10144a8b
void MxMediaManager::RegisterPresenter(MxPresenter& p_presenter)
{
	AUTOLOCK(m_criticalSection);

	this->m_presenters->Append(&p_presenter);
}

// FUNCTION: LEGO1 0x100b8980
// FUNCTION: BETA10 0x10144b0c
void MxMediaManager::UnregisterPresenter(MxPresenter& p_presenter)
{
	AUTOLOCK(m_criticalSection);
	MxPresenterListCursor cursor(this->m_presenters);

	if (cursor.Find(&p_presenter)) {
		cursor.Detach();
	}
}

// FUNCTION: LEGO1 0x100b8ac0
// FUNCTION: BETA10 0x10144bc3
void MxMediaManager::StopPresenters()
{
	AUTOLOCK(m_criticalSection);
	MxPresenter* presenter;
	MxPresenterListCursor cursor(this->m_presenters);

	while (cursor.Next(presenter)) {
		presenter->EndAction();
	}
}
