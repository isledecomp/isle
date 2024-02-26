#include "legoanimpresenter.h"

#include "legoomni.h"
#include "legounksavedatawriter.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxstreamchunk.h"
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
	m_unk0x68 = 0;
	m_unk0x6c = 0;
	m_unk0x74 = NULL;
	m_unk0x70 = NULL;
	m_unk0x78 = 0;
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
	m_unk0x96 = 1;
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

// STUB: LEGO1 0x10069150
LegoChar* LegoAnimPresenter::FUN_10069150(const LegoChar*)
{
	// TODO
	return NULL;
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

				roi = UnkSaveDataWriter()->FUN_10083500(src, TRUE);

				if (roi != NULL && str[0] == '*') {
					roi->SetUnknown0x0c(0);
				}
			}
			else if (unk0x04 == 4) {
				LegoChar* src = new LegoChar[strlen(str)];
				strcpy(src, str + 1);
				strlwr(src);

				LegoChar* und = FUN_10069150(str);
				roi = UnkSaveDataWriter()->FUN_10085a80(und, src, 1);

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
				roi = UnkSaveDataWriter()->FUN_10085210(und, src, 1);

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
		CompoundObject& unk0x08 = VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->GetUnknown0x08();
		LegoU32 numActors = m_anim->GetNumActors();

		for (LegoU32 i = 0; i < numActors; i++) {
			if (FUN_100698b0(unk0x08, m_anim->GetActorName(i)) == FALSE) {
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

					UnkSaveDataWriter()->FUN_10085210(str, dest, 0);
					FUN_100698b0(unk0x08, str);
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
LegoBool LegoAnimPresenter::FUN_100698b0(const CompoundObject& p_und1, const LegoChar* p_und2)
{
	LegoBool result = FALSE;

	LegoChar* str;
	if (*(str = FUN_100697c0(p_und2, NULL)) == '*') {
		LegoChar* tmp = FUN_10069150(str);
		delete[] str;
		str = tmp;
	}

	if (str != NULL && *str != '\0' && p_und1.size() > 0) {
		for (CompoundObject::iterator it = p_und1.begin(); it != p_und1.end(); it++) {
			LegoROI* roi = (LegoROI*) *it;
			const char* name = roi->GetName();

			if (name != NULL) {
				if (!strcmpi(name, str)) {
					m_unk0x70->Append(((LegoROI*) *it));
					result = TRUE;
					break;
				}
			}
		}
	}

	delete[] str;
	return result;
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

// STUB: LEGO1 0x1006b5e0
void LegoAnimPresenter::StartingTickle()
{
	// TODO
	ProgressTickleState(e_streaming);
	EndAction(); // Allow game to start
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
