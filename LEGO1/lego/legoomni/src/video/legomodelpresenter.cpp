#include "legomodelpresenter.h"

#include "define.h"
#include "legoentity.h"
#include "legoentitypresenter.h"
#include "legoomni.h"
#include "legounksavedatawriter.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxcompositepresenter.h"
#include "mxutil.h"
#include "roi/legoroi.h"

// GLOBAL: LEGO1 0x100f7ae0
int g_modelPresenterConfig = 1;

// GLOBAL: LEGO1 0x10102054
// STRING: LEGO1 0x10102018
char* g_autoCreate = "AUTO_CREATE";

// GLOBAL: LEGO1 0x10102078
// STRING: LEGO1 0x10101fc4
char* g_dbCreate = "DB_CREATE";

// FUNCTION: LEGO1 0x1000cca0
void LegoModelPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007f660
void LegoModelPresenter::configureLegoModelPresenter(MxS32 p_modelPresenterConfig)
{
	g_modelPresenterConfig = p_modelPresenterConfig;
}

// FUNCTION: LEGO1 0x1007f670
void LegoModelPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	m_roi = NULL;
	m_addedToView = FALSE;
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// STUB: LEGO1 0x1007f6b0
MxResult LegoModelPresenter::CreateROI(MxStreamChunk* p_chunk)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x10080050
void LegoModelPresenter::ReadyTickle()
{
	if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter") &&
		m_compositePresenter->GetCurrentTickleState() <= e_ready) {
		return;
	}

	ParseExtra();

	if (m_roi != NULL) {
		if (m_compositePresenter && m_compositePresenter->IsA("LegoEntityPresenter")) {
			((LegoEntityPresenter*) m_compositePresenter)->GetEntity()->SetROI((LegoROI*) m_roi, m_addedToView, TRUE);
			((LegoEntityPresenter*) m_compositePresenter)
				->GetEntity()
				->SetFlags(
					((LegoEntityPresenter*) m_compositePresenter)->GetEntity()->GetFlags() & ~LegoEntity::c_bit2
				);
			((LegoEntityPresenter*) m_compositePresenter)->GetEntity()->FUN_100114e0(0);
		}

		ParseExtra();
		ProgressTickleState(e_starting);
		EndAction();
	}
	else {
		MxStreamChunk* chunk = m_subscriber->PeekData();

		if (chunk != NULL && chunk->GetTime() <= m_action->GetElapsedTime()) {
			chunk = m_subscriber->PopData();
			MxResult result = CreateROI(chunk);
			m_subscriber->FreeDataChunk(chunk);

			if (result == SUCCESS) {
				VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_roi);
				VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);

				if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter")) {
					((LegoEntityPresenter*) m_compositePresenter)->GetEntity()->SetROI((LegoROI*) m_roi, TRUE, TRUE);
					((LegoEntityPresenter*) m_compositePresenter)
						->GetEntity()
						->SetFlags(
							((LegoEntityPresenter*) m_compositePresenter)->GetEntity()->GetFlags() & ~LegoEntity::c_bit2
						);
				}

				ParseExtra();
				ProgressTickleState(e_starting);
			}

			EndAction();
		}
	}
}

// FUNCTION: LEGO1 0x100801b0
void LegoModelPresenter::ParseExtra()
{
	char output[1024];

	MxU16 len = m_action->GetExtraLength();
	char* extraData = m_action->GetExtraData();

	if (len != 0) {
		char buffer[1024];
		output[0] = 0;
		memcpy(buffer, extraData, len);
		buffer[len] = 0;

		if (KeyValueStringParse(output, g_autoCreate, buffer) != 0) {
			char* token = strtok(output, g_parseExtraTokens);
			if (m_roi == NULL) {
				m_roi = UnkSaveDataWriter()->FUN_10083500(token, FALSE);
				m_addedToView = FALSE;
			}
		}
		else if (KeyValueStringParse(output, g_dbCreate, buffer) != 0 && m_roi == NULL) {
			LegoWorld* currentWorld = CurrentWorld();
			list<LegoROI*>& roiList = currentWorld->GetUnknownList0xe0();

			for (list<LegoROI*>::iterator it = roiList.begin(); it != roiList.end(); it++) {
				if (!strcmpi((*it)->GetName(), output)) {
					m_roi = *it;
					roiList.erase(it);

					m_addedToView = TRUE;
					VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_roi);
					VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);
					break;
				}
			}
		}
	}
}
