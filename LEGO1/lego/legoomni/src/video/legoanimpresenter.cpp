#include "legoanimpresenter.h"

#include "legoanimmmpresenter.h"
#include "legocharactermanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxmisc.h"
#include "mxstreamchunk.h"
#include "mxtimer.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(LegoAnimPresenter, 0xc0)

// FUNCTION: LEGO1 0x10068420
LegoAnimPresenter::LegoAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x10068670
LegoAnimPresenter::~LegoAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100686f0
void LegoAnimPresenter::Init()
{
	m_anim = NULL;
	m_unk0x68 = NULL;
	m_unk0x6c = 0;
	m_unk0x74 = NULL;
	m_unk0x70 = NULL;
	m_unk0x78 = NULL;
	m_unk0x7c = 0;
	m_unk0xa8.Clear();
	m_unk0xa4 = 0;
	m_currentWorld = NULL;
	m_unk0x95 = 0;
	m_unk0x88 = -1;
	m_unk0x98 = 0;
	m_animAtom.Clear();
	m_unk0x9c = 0;
	m_unk0x8c = 0;
	m_unk0x90 = 0;
	m_unk0x94 = 0;
	m_unk0x96 = TRUE;
	m_unk0xa0 = 0;
}

// STUB: LEGO1 0x10068770
void LegoAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
	MxVideoPresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x10068fb0
MxResult LegoAnimPresenter::CreateAnim(MxStreamChunk* p_chunk)
{
	MxResult result = FAILURE;
	LegoMemory storage(p_chunk->GetData());
	MxS32 magicSig;
	LegoS32 parseScene = 0;
	MxS32 val3;

	if (storage.Read(&magicSig, sizeof(magicSig)) != SUCCESS || magicSig != 0x11) {
		goto done;
	}
	if (storage.Read(&m_unk0xa4, sizeof(m_unk0xa4)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_unk0xa8[0], sizeof(m_unk0xa8[0])) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_unk0xa8[1], sizeof(m_unk0xa8[1])) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_unk0xa8[2], sizeof(m_unk0xa8[2])) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&parseScene, sizeof(parseScene)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&val3, sizeof(val3)) != SUCCESS) {
		goto done;
	}

	m_anim = new LegoAnim();
	if (!m_anim) {
		goto done;
	}

	if (m_anim->Read(&storage, parseScene) != SUCCESS) {
		goto done;
	}

	result = SUCCESS;

done:
	if (result != SUCCESS) {
		delete m_anim;
		Init();
	}

	return result;
}

// FUNCTION: LEGO1 0x10069150
LegoChar* LegoAnimPresenter::FUN_10069150(const LegoChar* p_und1)
{
	LegoChar* str;

	if (LegoCharacterManager::FUN_10084c00(p_und1 + 1)) {
		str = new LegoChar[strlen(p_und1)];

		if (str != NULL) {
			strcpy(str, p_und1 + 1);
		}
	}
	else {
		LegoChar buffer[32];
		sprintf(buffer, "%d", m_action->GetUnknown24());
		str = new LegoChar[strlen(p_und1) + strlen(buffer) + strlen(GetActionObjectName()) + 1];

		if (str != NULL) {
			strcpy(str, p_und1);
			strcat(str, buffer);
			strcat(str, GetActionObjectName());
		}
	}

	return str;
}

// FUNCTION: LEGO1 0x100692b0
void LegoAnimPresenter::FUN_100692b0()
{
	m_unk0x74 = new LegoROIList();

	if (m_unk0x74) {
		LegoU32 numActors = m_anim->GetNumActors();

		for (LegoU32 i = 0; i < numActors; i++) {
			LegoChar* str = FUN_100697c0(m_anim->GetActorName(i), NULL);
			undefined4 unk0x04 = m_anim->GetActorUnknown0x04(i);
			LegoROI* roi = NULL;

			if (unk0x04 == 2) {
				LegoChar* src;
				if (str[0] == '*') {
					src = str + 1;
				}
				else {
					src = str;
				}

				roi = CharacterManager()->FUN_10083500(src, TRUE);

				if (roi != NULL && str[0] == '*') {
					roi->SetUnknown0x0c(0);
				}
			}
			else if (unk0x04 == 4) {
				LegoChar* src = new LegoChar[strlen(str)];
				strcpy(src, str + 1);
				strlwr(src);

				LegoChar* und = FUN_10069150(str);
				roi = CharacterManager()->FUN_10085a80(und, src, 1);

				if (roi != NULL) {
					roi->SetUnknown0x0c(0);
				}

				delete[] src;
				delete[] und;
			}
			else if (unk0x04 == 3) {
				LegoChar* src = new LegoChar[strlen(str)];
				strcpy(src, str + 1);

				for (LegoChar* i = &src[strlen(src) - 1]; i > src; i--) {
					if ((*i < '0' || *i > '9') && *i != '_') {
						break;
					}

					*i = '\0';
				}

				strlwr(src);

				LegoChar* und = FUN_10069150(str);
				roi = CharacterManager()->FUN_10085210(und, src, 1);

				if (roi != NULL) {
					roi->SetUnknown0x0c(0);
				}

				delete[] src;
				delete[] und;
			}

			if (roi != NULL) {
				m_unk0x74->Append(roi);
			}

			delete[] str;
		}
	}
}

// FUNCTION: LEGO1 0x100695c0
void LegoAnimPresenter::FUN_100695c0()
{
	m_unk0x70 = new LegoROIList();

	if (m_unk0x70) {
		const CompoundObject& rois = VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->GetROIs();
		LegoU32 numActors = m_anim->GetNumActors();

		for (LegoU32 i = 0; i < numActors; i++) {
			if (FUN_100698b0(rois, m_anim->GetActorName(i)) == FALSE) {
				undefined4 unk0x04 = m_anim->GetActorUnknown0x04(i);

				if (unk0x04 == 5 || unk0x04 == 6) {
					LegoChar dest[256];
					const LegoChar* str = m_anim->GetActorName(i);

					LegoU32 len = strlen(str);
					strcpy(dest, str);

					for (LegoChar* i = &dest[len - 1]; isdigit(*i) || *i == '_'; i--) {
						*i = '\0';
					}

					strlwr(dest);

					CharacterManager()->FUN_10085210(str, dest, 0);
					FUN_100698b0(rois, str);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100697c0
LegoChar* LegoAnimPresenter::FUN_100697c0(const LegoChar* p_und1, const LegoChar* p_und2)
{
	const LegoChar* str = p_und1;
	const char* var = VariableTable()->GetVariable(p_und1);

	if (*var) {
		str = var;
	}

	LegoU32 len = strlen(str) + (p_und2 ? strlen(p_und2) : 0) + 2;
	LegoChar* result = new LegoChar[len];

	if (result != NULL) {
		*result = '\0';

		if (p_und2) {
			strcpy(result, p_und2);
			strcat(result, ":");
		}

		strcat(result, str);
	}

	return result;
}

// FUNCTION: LEGO1 0x100698b0
LegoBool LegoAnimPresenter::FUN_100698b0(const CompoundObject& p_rois, const LegoChar* p_und2)
{
	LegoBool result = FALSE;

	LegoChar* str;
	if (*(str = FUN_100697c0(p_und2, NULL)) == '*') {
		LegoChar* tmp = FUN_10069150(str);
		delete[] str;
		str = tmp;
	}

	if (str != NULL && *str != '\0' && p_rois.size() > 0) {
		for (CompoundObject::const_iterator it = p_rois.begin(); it != p_rois.end(); it++) {
			LegoROI* roi = (LegoROI*) *it;
			const char* name = roi->GetName();

			if (name != NULL) {
				if (!strcmpi(name, str)) {
					m_unk0x70->Append(roi);
					result = TRUE;
					break;
				}
			}
		}
	}

	delete[] str;
	return result;
}

// STUB: LEGO1 0x10069b10
void LegoAnimPresenter::FUN_10069b10()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006aba0
LegoBool LegoAnimPresenter::FUN_1006aba0()
{
	return FUN_1006abb0(m_anim->GetRoot(), 0);
}

// STUB: LEGO1 0x1006abb0
LegoBool LegoAnimPresenter::FUN_1006abb0(LegoTreeNode*, undefined4)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x1006ac90
void LegoAnimPresenter::FUN_1006ac90()
{
	// TODO
}

// STUB: LEGO1 0x1006ad30
void LegoAnimPresenter::PutFrame()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006b550
void LegoAnimPresenter::ReadyTickle()
{
	m_currentWorld = CurrentWorld();

	if (m_currentWorld) {
		MxStreamChunk* chunk = m_subscriber->PeekData();

		if (chunk && chunk->GetTime() + m_action->GetStartTime() <= m_action->GetElapsedTime()) {
			chunk = m_subscriber->PopData();
			MxResult result = CreateAnim(chunk);
			m_subscriber->FreeDataChunk(chunk);

			if (result == SUCCESS) {
				ProgressTickleState(e_starting);
				ParseExtra();
			}
			else {
				EndAction();
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006b5e0
void LegoAnimPresenter::StartingTickle()
{
	FUN_1006ac90();
	FUN_100692b0();
	FUN_100695c0();

	if ((m_unk0x7c & c_bit2) == 0 || FUN_1006aba0()) {
		FUN_10069b10();
		FUN_1006c8a0(TRUE);

		if (m_unk0x78 == NULL) {
			if (fabs(m_action->GetDirection().GetX()) >= 0.00000047683716F ||
				fabs(m_action->GetDirection().GetY()) >= 0.00000047683716F ||
				fabs(m_action->GetDirection().GetZ()) >= 0.00000047683716F) {
				m_unk0x78 = new MxMatrix();
				CalcLocalTransform(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp(), *m_unk0x78);
			}
			else if (m_unk0x68) {
				MxU8* und = (MxU8*) m_unk0x68[1];

				if (und) {
					MxMatrix mat;
					mat = *(Matrix4*) (und + 0x10);
					m_unk0x78 = new MxMatrix(mat);
				}
			}
		}

		if ((m_action->GetDuration() == -1 || ((MxDSMediaAction*) m_action)->GetSustainTime() == -1) &&
			m_compositePresenter) {
			m_compositePresenter->VTable0x60(this);
		}
		else {
			m_action->SetUnknown90(Timer()->GetTime());
		}

		ProgressTickleState(e_streaming);

		if (m_compositePresenter && m_compositePresenter->IsA("LegoAnimMMPresenter")) {
			m_unk0x96 = ((LegoAnimMMPresenter*) m_compositePresenter)->FUN_1004b8b0();
			m_compositePresenter->VTable0x60(this);
		}

		VTable0x8c();
	}

	if (m_unk0x70 != NULL) {
		delete m_unk0x70;
		m_unk0x70 = NULL;
	}
}

// FUNCTION: LEGO1 0x1006b840
void LegoAnimPresenter::StreamingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_unk0x95) {
		ProgressTickleState(e_done);
		if (m_compositePresenter) {
			if (m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				m_compositePresenter->VTable0x60(this);
			}
		}
	}
	else {
		if (m_action->GetElapsedTime() > m_anim->GetDuration() + m_action->GetStartTime()) {
			m_unk0x95 = 1;
		}
	}
}

// FUNCTION: LEGO1 0x1006b8c0
void LegoAnimPresenter::DoneTickle()
{
	MxVideoPresenter::DoneTickle();
}

// FUNCTION: LEGO1 0x1006b8d0
MxResult LegoAnimPresenter::AddToManager()
{
	return MxVideoPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006b8e0
void LegoAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1006b8f0
const char* LegoAnimPresenter::GetActionObjectName()
{
	return m_action->GetObjectName();
}

// STUB: LEGO1 0x1006bac0
void LegoAnimPresenter::ParseExtra()
{
	// TODO
}

// STUB: LEGO1 0x1006c570
void LegoAnimPresenter::VTable0xa0()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006c620
MxResult LegoAnimPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxVideoPresenter::StartAction(p_controller, p_action);
	m_displayZ = 0;
	return result;
}

// STUB: LEGO1 0x1006c640
void LegoAnimPresenter::EndAction()
{
	// TODO
	MxVideoPresenter::EndAction();
}

// STUB: LEGO1 0x1006c7d0
void LegoAnimPresenter::VTable0x8c()
{
	// TODO
}

// STUB: LEGO1 0x1006c860
void LegoAnimPresenter::VTable0x90()
{
	// TODO
}

// STUB: LEGO1 0x1006c8a0
void LegoAnimPresenter::FUN_1006c8a0(LegoBool)
{
	// TODO
}

// STUB: LEGO1 0x1006c8f0
void LegoAnimPresenter::VTable0x94()
{
	// TODO
}

// STUB: LEGO1 0x1006ca50
void LegoAnimPresenter::VTable0x98()
{
	// TODO
}
