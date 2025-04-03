#include "mxcontrolpresenter.h"

#include "define.h"
#include "legocontrolmanager.h"
#include "mxdsmultiaction.h"
#include "mxmisc.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxutilities.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxControlPresenter, 0x5c)

// FUNCTION: LEGO1 0x10043f50
MxControlPresenter::MxControlPresenter()
{
	m_unk0x4c = 0;
	m_unk0x4e = -1;
	m_unk0x50 = FALSE;
	m_unk0x52 = 0;
	m_states = NULL;
	m_unk0x54 = 0;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (m_states) {
		delete m_states;
	}
}

// FUNCTION: LEGO1 0x10044180
MxResult MxControlPresenter::AddToManager()
{
	m_unk0x4e = 0;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	FUN_100b7220(m_action, MxDSAction::c_world | MxDSAction::c_looping, TRUE);
	ParseExtra();

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable((m_unk0x4c != 3 || m_unk0x4e) && IsEnabled() ? m_unk0x4e == i : FALSE);
		i++;
	}

	if (m_unk0x4c == 3) {
		MxDSAction* action = (*m_list.begin())->GetAction();
		action->SetFlags(action->GetFlags() | MxDSAction::c_bit11);
	}

	TickleManager()->RegisterClient(this, 200);

	return result;
}

// FUNCTION: LEGO1 0x10044260
void MxControlPresenter::EndAction()
{
	if (m_action) {
		m_unk0x50 = TRUE;
		MxCompositePresenter::EndAction();
	}
}

// FUNCTION: LEGO1 0x10044270
// FUNCTION: BETA10 0x100eae68
MxBool MxControlPresenter::FUN_10044270(MxS32 p_x, MxS32 p_y, MxPresenter* p_presenter)
{
	assert(p_presenter);
	MxStillPresenter* presenter = (MxStillPresenter*) p_presenter;

	if (m_unk0x4c == 3) {
		MxStillPresenter* map = (MxStillPresenter*) m_list.front();
		assert(map && map->IsA("MxStillPresenter"));

		if (presenter == map || map->GetDisplayZ() < presenter->GetDisplayZ()) {
			if (map->VTable0x7c()) {
				MxRect32 rect(0, 0, map->GetWidth() - 1, map->GetHeight() - 1);
				rect += map->GetLocation();

				if (rect.GetLeft() <= p_x && p_x < rect.GetRight() && rect.GetTop() <= p_y && p_y < rect.GetBottom()) {
					// DECOMP: Beta uses GetBitmapStart() here, but that causes more diffs for retail.
					MxU8* start = map->GetAlphaMask()
									  ? NULL
									  : map->GetBitmap()->GetStart(p_x - rect.GetLeft(), p_y - rect.GetTop());

					m_unk0x56 = 0;
					if (m_states) {
						for (MxS16 i = 1; i <= *m_states; i++) {
							// TODO: Can we match without the cast here?
							if (m_states[i] == (MxS16) *start) {
								m_unk0x56 = i;
								break;
							}
						}
					}
					else {
						if (*start != 0) {
							m_unk0x56 = 1;
						}
					}

					if (m_unk0x56) {
						return TRUE;
					}
				}
			}
		}
	}
	else {
		if (ContainsPresenter(m_list, presenter)) {
			if (m_unk0x4c == 2) {
				MxS32 width = presenter->GetWidth();
				MxS32 height = presenter->GetHeight();

				if (m_unk0x52 == 2 && m_unk0x54 == 2) {
					if (p_x < presenter->GetX() + width / 2) {
						m_unk0x56 = (p_y >= presenter->GetY() + height / 2) ? 3 : 1;
					}
					else {
						m_unk0x56 = (p_y >= presenter->GetY() + height / 2) ? 4 : 2;
					}
				}
			}
			else {
				m_unk0x56 = -1;
			}

			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044480
MxBool MxControlPresenter::FUN_10044480(LegoControlManagerNotificationParam* p_param, MxPresenter* p_presenter)
{
	if (IsEnabled()) {
		switch (p_param->GetNotification()) {
		case c_notificationButtonUp:
			if (m_unk0x4c == 0 || m_unk0x4c == 2 || m_unk0x4c == 3) {
				p_param->SetClickedObjectId(m_action->GetObjectId());
				p_param->SetClickedAtom(m_action->GetAtomId().GetInternal());
				VTable0x6c(0);
				p_param->SetNotification(c_notificationControl);
				p_param->SetUnknown0x28(m_unk0x4e);
				return TRUE;
			}
			break;
		case c_notificationButtonDown:
			if (FUN_10044270(p_param->GetX(), p_param->GetY(), p_presenter)) {
				p_param->SetClickedObjectId(m_action->GetObjectId());
				p_param->SetClickedAtom(m_action->GetAtomId().GetInternal());
				VTable0x6c(m_unk0x56);
				p_param->SetNotification(c_notificationControl);
				p_param->SetUnknown0x28(m_unk0x4e);
				return TRUE;
			}
			break;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044540
void MxControlPresenter::VTable0x6c(MxS16 p_unk0x4e)
{
	if (p_unk0x4e == -1) {
		if ((MxS16) ((MxDSMultiAction*) m_action)->GetActionList()->GetNumElements() - m_unk0x4e == 1) {
			m_unk0x4e = 0;
		}
		else {
			m_unk0x4e++;
		}
	}
	else {
		m_unk0x4e = p_unk0x4e;
	}

	m_action->SetUnknown90(Timer()->GetTime());

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable(((m_unk0x4c == 3 && m_unk0x4e == 0) || !IsEnabled()) ? FALSE : m_unk0x4e == i);
		i++;
	}
}

// FUNCTION: LEGO1 0x10044610
void MxControlPresenter::ReadyTickle()
{
	MxPresenter::ParseExtra();
	TickleManager()->UnregisterClient(this);
	ProgressTickleState(e_repeating);
}

// FUNCTION: LEGO1 0x10044640
// FUNCTION: BETA10 0x100eb5e3
void MxControlPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength) {
		char extraCopy[256];
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		char output[256];
		if (KeyValueStringParse(output, g_strSTYLE, extraCopy)) {
			char* token = strtok(output, g_parseExtraTokens);

			if (!strcmpi(token, g_strTOGGLE)) {
				m_unk0x4c = 1;
			}
			else if (!strcmpi(token, g_strGRID)) {
				m_unk0x4c = 2;
				token = strtok(NULL, g_parseExtraTokens);
				assert(token);
				m_unk0x52 = atoi(token);

				token = strtok(NULL, g_parseExtraTokens);
				assert(token);
				m_unk0x54 = atoi(token);
			}
			else if (!strcmpi(token, g_strMAP)) {
				m_unk0x4c = 3;
				token = strtok(NULL, g_parseExtraTokens);

				if (token) {
					MxS16 numStates = atoi(token);
					m_states = new MxS16[numStates + 1];
					assert(numStates);
					*m_states = numStates;

					for (MxS16 i = 1; i <= numStates; i++) {
						token = strtok(NULL, g_parseExtraTokens);
						assert(token);
						m_states[i] = atoi(token);
					}
				}
			}
			else {
				m_unk0x4c = 0;
			}
		}

		if (KeyValueStringParse(output, g_strVISIBILITY, extraCopy)) {
			if (!strcmpi(output, "FALSE")) {
				Enable(FALSE);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10044820
void MxControlPresenter::Enable(MxBool p_enable)
{
	if (MxPresenter::IsEnabled() != p_enable) {
		MxPresenter::Enable(p_enable);

		MxS16 i = 0;
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if (i == m_unk0x4e) {
				(*it)->Enable((m_unk0x4c != 3 || i != 0) ? p_enable : 0);
				break;
			}

			i++;
		}

		if (!p_enable) {
			m_unk0x4e = 0;
		}
	}
}

// FUNCTION: LEGO1 0x100448a0
MxBool MxControlPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	MxCompositePresenterList::const_iterator it = m_list.begin();

#ifdef COMPAT_MODE
	advance(it, m_unk0x4e);
#else
	// Uses forward iterator logic instead of bidrectional for some reason.
	_Advance(it, m_unk0x4e, forward_iterator_tag());
#endif

	return (*it)->HasTickleStatePassed(p_tickleState);
}
