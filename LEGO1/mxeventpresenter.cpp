#include "mxeventpresenter.h"

#include "decomp.h"
#include "mxeventmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(MxEventPresenter, 0x54);

// OFFSET: LEGO1 0x100c2b70
MxEventPresenter::MxEventPresenter()
{
	Init();
}

// OFFSET: LEGO1 0x100c2d40
MxEventPresenter::~MxEventPresenter()
{
	Destroy();
}

// OFFSET: LEGO1 0x100c2da0
void MxEventPresenter::Init()
{
	m_unk50 = NULL;
}

// OFFSET: LEGO1 0x100c2db0
MxResult MxEventPresenter::AddToManager()
{
	MxResult ret = FAILURE;
	if (EventManager()) {
		ret = SUCCESS;
		EventManager()->AddPresenter(*this);
	}

	return ret;
}

// OFFSET: LEGO1 0x100c2de0
void MxEventPresenter::Destroy()
{
	if (EventManager())
		EventManager()->RemovePresenter(*this);

	m_criticalSection.Enter();

	if (m_unk50)
		delete m_unk50;

	Init();

	m_criticalSection.Leave();
}
