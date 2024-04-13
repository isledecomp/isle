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
#include "realtime/realtime.h"

DECOMP_SIZE_ASSERT(LegoAnimPresenter, 0xbc)

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
	m_unk0x8c = NULL;
	m_unk0x90 = NULL;
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

	if (LegoCharacterManager::Exists(p_und1 + 1)) {
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

				roi = CharacterManager()->GetROI(src, TRUE);

				if (roi != NULL && str[0] == '*') {
					roi->SetVisibility(FALSE);
				}
			}
			else if (unk0x04 == 4) {
				LegoChar* baseName = new LegoChar[strlen(str)];
				strcpy(baseName, str + 1);
				strlwr(baseName);

				LegoChar* und = FUN_10069150(str);
				roi = CharacterManager()->FUN_10085a80(und, baseName, TRUE);

				if (roi != NULL) {
					roi->SetVisibility(FALSE);
				}

				delete[] baseName;
				delete[] und;
			}
			else if (unk0x04 == 3) {
				LegoChar* lodName = new LegoChar[strlen(str)];
				strcpy(lodName, str + 1);

				for (LegoChar* i = &lodName[strlen(lodName) - 1]; i > lodName; i--) {
					if ((*i < '0' || *i > '9') && *i != '_') {
						break;
					}

					*i = '\0';
				}

				strlwr(lodName);

				LegoChar* und = FUN_10069150(str);
				roi = CharacterManager()->FUN_10085210(und, lodName, TRUE);

				if (roi != NULL) {
					roi->SetVisibility(FALSE);
				}

				delete[] lodName;
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
					LegoChar lodName[256];
					const LegoChar* actorName = m_anim->GetActorName(i);

					LegoU32 len = strlen(actorName);
					strcpy(lodName, actorName);

					for (LegoChar* i = &lodName[len - 1]; isdigit(*i) || *i == '_'; i--) {
						*i = '\0';
					}

					strlwr(lodName);

					CharacterManager()->FUN_10085210(actorName, lodName, FALSE);
					FUN_100698b0(rois, actorName);
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

// FUNCTION: LEGO1 0x100699e0
LegoROI* LegoAnimPresenter::FUN_100699e0(const LegoChar* p_und)
{
	LegoROIListCursor cursor(m_unk0x70);
	LegoROI* roi;

	while (cursor.Next(roi)) {
		LegoChar* und = FUN_100697c0(roi->GetName(), NULL);

		if (und != NULL && !strcmpi(und, p_und)) {
			delete[] und;
			return roi;
		}

		delete[] und;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10069b10
void LegoAnimPresenter::FUN_10069b10()
{
	LegoAnimPresenterMap map;

	if (m_unk0x8c != NULL) {
		memset(m_unk0x8c, 0, m_unk0x94 * sizeof(*m_unk0x8c));
	}

	FUN_1006a3c0(map, m_anim->GetRoot(), NULL);

	if (m_unk0x68 != NULL) {
		delete[] m_unk0x68;
		m_unk0x6c = 0;
	}

	m_unk0x6c = 0;
	m_unk0x68 = new LegoROI*[map.size() + 1];
	memset(m_unk0x68, 0, (map.size() + 1) * sizeof(*m_unk0x68));

	for (LegoAnimPresenterMap::iterator it = map.begin(); it != map.end();) {
		MxU32 index = (*it).second.m_index;
		m_unk0x68[index] = (*it).second.m_roi;

		if (m_unk0x68[index]->GetName() != NULL) {
			for (MxS32 i = 0; i < m_unk0x94; i++) {
				if (m_unk0x8c[i] == NULL && m_unk0x90[i] != NULL) {
					if (!strcmpi(m_unk0x90[i], m_unk0x68[index]->GetName())) {
						m_unk0x8c[i] = m_unk0x68[index];
						break;
					}
				}
			}
		}

		delete[] const_cast<char*>((*it).first);
		it++;
		m_unk0x6c++;
	}
}

// FUNCTION: LEGO1 0x1006a3c0
void LegoAnimPresenter::FUN_1006a3c0(LegoAnimPresenterMap& p_map, LegoTreeNode* p_node, LegoROI* p_roi)
{
	LegoROI* roi = p_roi;
	LegoChar* und = NULL;
	LegoChar* und2 = NULL;
	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	const LegoChar* name = data->GetName();

	if (name != NULL && *name != '-') {
		if (*name == '*') {
			name = und2 = FUN_10069150(name);
		}

		und = FUN_100697c0(name, p_roi != NULL ? p_roi->GetName() : NULL);

		if (p_roi == NULL) {
			roi = FUN_100699e0(und);

			if (roi != NULL) {
				FUN_1006a4f0(p_map, data, und, roi);
			}
			else {
				data->SetUnknown0x20(0);
			}
		}
		else {
			LegoROI* roi2 = p_roi->FUN_100a8ce0(name, p_roi);

			if (roi2 != NULL) {
				FUN_1006a4f0(p_map, data, und, roi2);
			}
			else {
				if (FUN_100699e0(name) != NULL) {
					FUN_1006a3c0(p_map, p_node, NULL);
					delete[] und;
					delete[] und2;
					return;
				}
			}
		}
	}

	delete[] und;
	delete[] und2;

	MxS32 count = p_node->GetNumChildren();
	for (MxS32 i = 0; i < count; i++) {
		FUN_1006a3c0(p_map, p_node->GetChild(i), roi);
	}
}

// FUNCTION: LEGO1 0x1006a4f0
void LegoAnimPresenter::FUN_1006a4f0(
	LegoAnimPresenterMap& p_map,
	LegoAnimNodeData* p_data,
	const LegoChar* p_und,
	LegoROI* p_roi
)
{
	LegoAnimPresenterMap::iterator it;

	it = p_map.find(p_und);
	if (it == p_map.end()) {
		LegoAnimStruct animStruct;
		animStruct.m_index = p_map.size() + 1;
		animStruct.m_roi = p_roi;

		p_data->SetUnknown0x20(animStruct.m_index);

		LegoChar* und = new LegoChar[strlen(p_und) + 1];
		strcpy(und, p_und);

		p_map[und] = animStruct;
	}
	else {
		p_data->SetUnknown0x20((*it).second.m_index);
	}
}

// FUNCTION: LEGO1 0x1006aba0
LegoBool LegoAnimPresenter::FUN_1006aba0()
{
	return FUN_1006abb0(m_anim->GetRoot(), 0);
}

// FUNCTION: LEGO1 0x1006abb0
MxBool LegoAnimPresenter::FUN_1006abb0(LegoTreeNode* p_node, LegoROI* p_roi)
{
	MxBool result = FALSE;
	LegoROI* roi = p_roi;
	LegoChar* und = NULL;
	const LegoChar* name = ((LegoAnimNodeData*) p_node->GetData())->GetName();
	MxS32 i, count;

	if (name != NULL && *name != '-') {
		und = FUN_100697c0(name, p_roi != NULL ? p_roi->GetName() : NULL);

		if (p_roi == NULL) {
			roi = FUN_100699e0(und);

			if (roi == NULL) {
				goto done;
			}
		}
		else {
			LegoROI* roi2 = p_roi->FUN_100a8ce0(name, p_roi);

			if (roi2 == NULL) {
				if (FUN_100699e0(name) != NULL) {
					if (FUN_1006abb0(p_node, NULL)) {
						result = TRUE;
					}
				}

				goto done;
			}
		}
	}

	count = p_node->GetNumChildren();
	for (i = 0; i < count; i++) {
		if (!FUN_1006abb0(p_node->GetChild(i), roi)) {
			goto done;
		}
	}

	result = TRUE;

done:
	if (und != NULL) {
		delete[] und;
	}

	return result;
}

// STUB: LEGO1 0x1006ac90
void LegoAnimPresenter::FUN_1006ac90()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006ad30
void LegoAnimPresenter::PutFrame()
{
	if (m_currentTickleState == e_streaming) {
		MxLong time;

		if (m_action->GetStartTime() <= m_action->GetElapsedTime()) {
			time = m_action->GetElapsedTime() - m_action->GetStartTime();
		}
		else {
			time = 0;
		}

		FUN_1006b9a0(m_anim, time, m_unk0x78);

		if (m_unk0x8c != NULL && m_currentWorld != NULL && m_currentWorld->GetCamera() != NULL) {
			for (MxS32 i = 0; i < m_unk0x94; i++) {
				if (m_unk0x8c[i] != NULL) {
					MxMatrix mat(m_unk0x8c[i]->GetLocal2World());

					Vector3 pos(mat[0]);
					Vector3 dir(mat[1]);
					Vector3 up(mat[2]);
					Vector3 und(mat[3]);

					float possqr = sqrt(pos.LenSquared());
					float dirsqr = sqrt(dir.LenSquared());
					float upsqr = sqrt(up.LenSquared());

					up = und;

#ifdef COMPAT_MODE
					Mx3DPointFloat location = m_currentWorld->GetCamera()->GetWorldLocation();
					((Vector3&) up).Sub(&location);
#else
					((Vector3&) up).Sub(&m_currentWorld->GetCamera()->GetWorldLocation());
#endif
					((Vector3&) dir).Div(dirsqr);
					pos.EqualsCross(&dir, &up);
					pos.Unitize();
					up.EqualsCross(&pos, &dir);
					((Vector3&) pos).Mul(possqr);
					((Vector3&) dir).Mul(dirsqr);
					((Vector3&) up).Mul(upsqr);

					m_unk0x8c[i]->FUN_100a58f0(mat);
					m_unk0x8c[i]->VTable0x14();
				}
			}
		}
	}
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

	if (m_unk0x7c & c_bit2 && !FUN_1006aba0()) {
		goto done;
	}

	FUN_10069b10();
	FUN_1006c8a0(TRUE);

	if (m_unk0x78 == NULL) {
		if (fabs(m_action->GetDirection().GetX()) >= 0.00000047683716F ||
			fabs(m_action->GetDirection().GetY()) >= 0.00000047683716F ||
			fabs(m_action->GetDirection().GetZ()) >= 0.00000047683716F) {
			m_unk0x78 = new MxMatrix();
			CalcLocalTransform(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp(), *m_unk0x78);
		}
		else if (m_unk0x68 != NULL) {
			LegoROI* roi = m_unk0x68[1];

			if (roi != NULL) {
				MxMatrix mat;
				mat = roi->GetLocal2World();
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

done:
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

// FUNCTION: LEGO1 0x1006b9a0
void LegoAnimPresenter::FUN_1006b9a0(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix)
{
	LegoTreeNode* root = p_anim->GetRoot();
	MxMatrix mat;
	LegoAnimNodeData* data = (LegoAnimNodeData*) root->GetData();

	if (p_matrix != NULL) {
		mat = *p_matrix;
	}
	else {
		LegoROI* roi = m_unk0x68[data->GetUnknown0x20()];

		if (roi != NULL) {
			mat = roi->GetLocal2World();
		}
		else {
			mat.SetIdentity();
		}
	}

	if (p_anim->GetScene() != NULL) {
		MxMatrix transform(mat);
		p_anim->GetScene()->FUN_1009f490(p_time, transform);

		if (m_currentWorld != NULL && m_currentWorld->GetCamera() != NULL) {
			m_currentWorld->GetCamera()->FUN_100123e0(transform, 0);
		}
	}

	LegoROI::FUN_100a8e80(root, mat, p_time, m_unk0x68);
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

// FUNCTION: LEGO1 0x1006c8a0
void LegoAnimPresenter::FUN_1006c8a0(MxBool p_bool)
{
	if (m_unk0x6c != 0 && m_unk0x68 != NULL) {
		for (MxU32 i = 1; i <= m_unk0x6c; i++) {
			LegoEntity* entity = m_unk0x68[i]->GetEntity();

			if (entity != NULL) {
				if (p_bool) {
					entity->SetUnknown0x10Flag(LegoEntity::c_altBit1);
				}
				else {
					entity->ClearUnknown0x10Flag(LegoEntity::c_altBit1);
				}
			}
		}
	}
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

// STUB: LEGO1 0x1006d680
void LegoAnimPresenter::FUN_1006d680(LegoAnimActor* p_actor, MxFloat p_value)
{
	// TODO
}
