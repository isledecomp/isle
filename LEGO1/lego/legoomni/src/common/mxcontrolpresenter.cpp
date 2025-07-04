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
	m_style = e_none;
	m_enabledChild = -1;
	m_unk0x50 = FALSE;
	m_columnsOrRows = 0;
	m_states = NULL;
	m_rowsOrColumns = 0;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (m_states) {
		delete[] m_states;
	}
}

// FUNCTION: LEGO1 0x10044180
MxResult MxControlPresenter::AddToManager()
{
	m_enabledChild = 0;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	ApplyMask(m_action, MxDSAction::c_world | MxDSAction::c_looping, TRUE);
	ParseExtra();

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable((m_style != e_map || m_enabledChild) && IsEnabled() ? m_enabledChild == i : FALSE);
		i++;
	}

	if (m_style == e_map) {
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
MxBool MxControlPresenter::CheckButtonDown(MxS32 p_x, MxS32 p_y, MxPresenter* p_presenter)
{
	assert(p_presenter);
	MxVideoPresenter* presenter = (MxVideoPresenter*) p_presenter;

	if (m_style == e_map) {
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

					m_stateOrCellIndex = 0;
					if (m_states) {
						for (MxS16 i = 1; i <= *m_states; i++) {
							// TODO: Can we match without the cast here?
							if (m_states[i] == (MxS16) *start) {
								m_stateOrCellIndex = i;
								break;
							}
						}
					}
					else {
						if (*start != 0) {
							m_stateOrCellIndex = 1;
						}
					}

					if (m_stateOrCellIndex) {
						return TRUE;
					}
				}
			}
		}
	}
	else {
		if (ContainsPresenter(m_list, presenter)) {
			if (m_style == e_grid) {
				MxS32 width = presenter->GetWidth();
				MxS32 height = presenter->GetHeight();

				if (m_columnsOrRows == 2 && m_rowsOrColumns == 2) {
					if (p_x < presenter->GetX() + width / 2) {
						m_stateOrCellIndex = (p_y >= presenter->GetY() + height / 2) ? 3 : 1;
					}
					else {
						m_stateOrCellIndex = (p_y >= presenter->GetY() + height / 2) ? 4 : 2;
					}
				}
			}
			else {
				m_stateOrCellIndex = -1;
			}

			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044480
MxBool MxControlPresenter::Notify(LegoControlManagerNotificationParam* p_param, MxPresenter* p_presenter)
{
	if (IsEnabled()) {
		switch (p_param->GetNotification()) {
		case c_notificationButtonUp:
			if (m_style == e_none || m_style == e_grid || m_style == e_map) {
				p_param->SetClickedObjectId(m_action->GetObjectId());
				p_param->SetClickedAtom(m_action->GetAtomId().GetInternal());
				UpdateEnabledChild(0);
				p_param->SetNotification(c_notificationControl);
				p_param->SetUnknown0x28(m_enabledChild);
				return TRUE;
			}
			break;
		case c_notificationButtonDown:
			if (CheckButtonDown(p_param->GetX(), p_param->GetY(), p_presenter)) {
				p_param->SetClickedObjectId(m_action->GetObjectId());
				p_param->SetClickedAtom(m_action->GetAtomId().GetInternal());
				UpdateEnabledChild(m_stateOrCellIndex);
				p_param->SetNotification(c_notificationControl);
				p_param->SetUnknown0x28(m_enabledChild);
				return TRUE;
			}
			break;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10044540
void MxControlPresenter::UpdateEnabledChild(MxS16 p_enabledChild)
{
	if (p_enabledChild == -1) {
		if ((MxS16) ((MxDSMultiAction*) m_action)->GetActionList()->GetNumElements() - m_enabledChild == 1) {
			m_enabledChild = 0;
		}
		else {
			m_enabledChild++;
		}
	}
	else {
		m_enabledChild = p_enabledChild;
	}

	m_action->SetTimeStarted(Timer()->GetTime());

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable(((m_style == e_map && m_enabledChild == 0) || !IsEnabled()) ? FALSE : m_enabledChild == i);
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
				m_style = e_toggle;
			}
			else if (!strcmpi(token, g_strGRID)) {
				m_style = e_grid;
				token = strtok(NULL, g_parseExtraTokens);
				assert(token);
				m_columnsOrRows = atoi(token);

				token = strtok(NULL, g_parseExtraTokens);
				assert(token);
				m_rowsOrColumns = atoi(token);
			}
			else if (!strcmpi(token, g_strMAP)) {
				m_style = e_map;
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
				m_style = e_none;
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
			if (i == m_enabledChild) {
				(*it)->Enable((m_style != e_map || i != 0) ? p_enable : 0);
				break;
			}

			i++;
		}

		if (!p_enable) {
			m_enabledChild = 0;
		}
	}
}

// FUNCTION: LEGO1 0x100448a0
MxBool MxControlPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	MxCompositePresenterList::const_iterator it = m_list.begin();

#ifdef COMPAT_MODE
	advance(it, m_enabledChild);
#else
	// Uses forward iterator logic instead of bidrectional for some reason.
	_Advance(it, m_enabledChild, forward_iterator_tag());
#endif

	return (*it)->HasTickleStatePassed(p_tickleState);
}
