#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// OFFSET: LEGO1 0x1000caf0
MxBool MxCompositePresenter::VTable0x64(undefined4 p_unknown)
{
	if (m_compositePresenter)
		return m_compositePresenter->VTable0x64(p_unknown);
	return TRUE;
}

// OFFSET: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
	NotificationManager()->Register(this);
}

// OFFSET: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
	NotificationManager()->Unregister(this);
}

// OFFSET: LEGO1 0x100b67f0 STUB
void MxCompositePresenter::VTable0x58()
{
	// TODO
}

// OFFSET: LEGO1 0x100b69b0 STUB
void MxCompositePresenter::VTable0x5c()
{
	// TODO
}

// OFFSET: LEGO1 0x100b6b40
void MxCompositePresenter::VTable0x60(MxPresenter* p_presenter)
{
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (*it == p_presenter) {
			if (++it == m_list.end()) {
				if (m_compositePresenter)
					m_compositePresenter->VTable0x60(this);
			}
			else if (m_action->IsA("MxDSSerialAction")) {
				MxPresenter* presenter = *it;
				if (!presenter->GetCurrentTickleState())
					presenter->SetTickleState(TickleState_Ready);
			}
			return;
		}
	}
}
