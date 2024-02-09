#include "legomodelpresenter.h"

#include "legoentity.h"
#include "legoentitypresenter.h"
#include "legoomni.h"
#include "legovideomanager.h"
#include "mxcompositepresenter.h"

// GLOBAL: LEGO1 0x100f7ae0
int g_modelPresenterConfig = 1;

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
	m_unk0x64 = 0;
	m_addedToView = FALSE;
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// STUB: LEGO1 0x1007f6b0
undefined4 LegoModelPresenter::LoadModel(MxStreamChunk* p_chunk)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10080050
void LegoModelPresenter::ReadyTickle()
{
	if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter") &&
		m_compositePresenter->GetCurrentTickleState() <= e_ready) {
		return;
	}

	ParseExtra();

	if (m_unk0x64 != NULL) {
		if (m_compositePresenter && m_compositePresenter->IsA("LegoEntityPresenter")) {
			((LegoEntityPresenter*) m_compositePresenter)
				->GetEntity()
				->SetROI((LegoROI*) m_unk0x64, m_addedToView, TRUE);
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
		MxStreamChunk* chunk = m_subscriber->CurrentChunk();

		if (chunk != NULL && chunk->GetTime() <= m_action->GetElapsedTime()) {
			chunk = m_subscriber->NextChunk();
			undefined4 und = LoadModel(chunk);
			m_subscriber->DestroyChunk(chunk);

			if (und == 0) {
				VideoManager()->Get3DManager()->GetLego3DView()->Add(*m_unk0x64);
				VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_unk0x64);

				if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoEntityPresenter")) {
					((LegoEntityPresenter*) m_compositePresenter)
						->GetEntity()
						->SetROI((LegoROI*) m_unk0x64, TRUE, TRUE);
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

// STUB: LEGO1 0x100801b0
void LegoModelPresenter::ParseExtra()
{
	// TODO
}
