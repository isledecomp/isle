#include "legoanimpresenter.h"

#include "3dmanager/lego3dmanager.h"
#include "anim/legoanim.h"
#include "define.h"
#include "legoanimactor.h"
#include "legoanimationmanager.h"
#include "legoanimmmpresenter.h"
#include "legocameracontroller.h"
#include "legocharactermanager.h"
#include "legoendanimnotificationparam.h"
#include "legopathboundary.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxdssubscriber.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstreamchunk.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "mxvariabletable.h"
#include "mxvideomanager.h"
#include "realtime/realtime.h"
#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(LegoAnimPresenter, 0xbc)
DECOMP_SIZE_ASSERT(LegoLoopingAnimPresenter, 0xc0)
DECOMP_SIZE_ASSERT(LegoLocomotionAnimPresenter, 0xd8)
DECOMP_SIZE_ASSERT(LegoHideAnimPresenter, 0xc4)
DECOMP_SIZE_ASSERT(LegoHideAnimStruct, 0x08)

// FUNCTION: LEGO1 0x10068420
// FUNCTION: BETA10 0x1004e5f0
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
	m_roiMap = NULL;
	m_roiMapSize = 0;
	m_managedActors = NULL;
	m_sceneROIs = NULL;
	m_transform = NULL;
	m_flags = 0;
	m_centerPoint.Clear();
	m_boundingRadius = 0;
	m_currentWorld = NULL;
	m_animationFinished = FALSE;
	m_worldId = -1;
	m_substMap = NULL;
	m_worldAtom.Clear();
	m_roiTransformApplied = 0;
	m_ptAtCamROI = NULL;
	m_ptAtCamNames = NULL;
	m_ptAtCamCount = 0;
	m_localActors = TRUE;
	m_roiTransform = NULL;
}

// FUNCTION: LEGO1 0x10068770
// FUNCTION: BETA10 0x1004e833
void LegoAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	{
		AUTOLOCK(m_criticalSection);

		if (m_anim != NULL) {
			delete m_anim;
		}

		if (m_roiMap != NULL) {
			delete[] m_roiMap;
		}

		if (m_sceneROIs != NULL) {
			delete m_sceneROIs;
		}

		if (m_managedActors != NULL) {
			ReleaseManagedActors();
			delete m_managedActors;
		}

		if (m_transform != NULL) {
			delete m_transform;
		}

		if (m_substMap != NULL) {
			MxVariableTable* variableTable = VariableTable();

			for (LegoAnimSubstMap::iterator it = m_substMap->begin(); it != m_substMap->end(); it++) {
				variableTable->SetVariable((*it).first, "");

				delete[] const_cast<char*>((*it).first);
				delete[] const_cast<char*>((*it).second);
			}

			delete m_substMap;
		}

		if (m_ptAtCamNames != NULL) {
			for (MxS32 i = 0; i < m_ptAtCamCount; i++) {
				if (m_ptAtCamNames[i] != NULL) {
					delete[] m_ptAtCamNames[i];
				}
			}

			delete[] m_ptAtCamNames;
		}

		if (m_ptAtCamROI != NULL) {
			delete[] m_ptAtCamROI;
		}

		if (m_roiTransform != NULL) {
			delete m_roiTransform;
		}

		Init();
	}

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x10068fb0
MxResult LegoAnimPresenter::CreateAnim(MxStreamChunk* p_chunk)
{
	MxResult result = FAILURE;
	LegoMemory storage(p_chunk->GetData());
	MxS32 magicSig;
	LegoS32 parseScene = 0;
	MxS32 val3;

	if (storage.Read(&magicSig, sizeof(MxS32)) != SUCCESS || magicSig != 0x11) {
		goto done;
	}
	if (storage.Read(&m_boundingRadius, sizeof(float)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_centerPoint[0], sizeof(float)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_centerPoint[1], sizeof(float)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&m_centerPoint[2], sizeof(float)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&parseScene, sizeof(LegoS32)) != SUCCESS) {
		goto done;
	}
	if (storage.Read(&val3, sizeof(MxS32)) != SUCCESS) {
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
LegoChar* LegoAnimPresenter::GetActorName(const LegoChar* p_name)
{
	LegoChar* str;

	if (LegoCharacterManager::IsActor(p_name + 1)) {
		str = new LegoChar[strlen(p_name)];

		if (str != NULL) {
			strcpy(str, p_name + 1);
		}
	}
	else {
		LegoChar buffer[32];
		sprintf(buffer, "%d", m_action->GetUnknown24());
		str = new LegoChar[strlen(p_name) + strlen(buffer) + strlen(GetActionObjectName()) + 1];

		if (str != NULL) {
			strcpy(str, p_name);
			strcat(str, buffer);
			strcat(str, GetActionObjectName());
		}
	}

	return str;
}

// FUNCTION: LEGO1 0x100692b0
void LegoAnimPresenter::CreateManagedActors()
{
	m_managedActors = new LegoROIList();

	if (m_managedActors) {
		LegoU32 numActors = m_anim->GetNumActors();

		for (LegoU32 i = 0; i < numActors; i++) {
			LegoChar* str = GetVariableOrIdentity(m_anim->GetActorName(i), NULL);
			LegoU32 actorType = m_anim->GetActorType(i);
			LegoROI* roi = NULL;

			if (actorType == LegoAnimActorEntry::e_managedLegoActor) {
				LegoChar* src;
				if (str[0] == '*') {
					src = str + 1;
				}
				else {
					src = str;
				}

				roi = CharacterManager()->GetActorROI(src, TRUE);

				if (roi != NULL && str[0] == '*') {
					roi->SetVisibility(FALSE);
				}
			}
			else if (actorType == LegoAnimActorEntry::e_managedInvisibleRoi) {
				LegoChar* baseName = new LegoChar[strlen(str)];
				strcpy(baseName, str + 1);
				strlwr(baseName);

				LegoChar* roiName = GetActorName(str);
				roi = CharacterManager()->FUN_10085a80(roiName, baseName, TRUE);

				if (roi != NULL) {
					roi->SetVisibility(FALSE);
				}

				delete[] baseName;
				delete[] roiName;
			}
			else if (actorType == LegoAnimActorEntry::e_managedInvisibleRoiTrimmed) {
				LegoChar* lodName = new LegoChar[strlen(str)];
				strcpy(lodName, str + 1);

				for (LegoChar* c = &lodName[strlen(lodName) - 1]; c > lodName; c--) {
					if ((*c < '0' || *c > '9') && *c != '_') {
						break;
					}

					*c = '\0';
				}

				strlwr(lodName);

				LegoChar* roiName = GetActorName(str);
				roi = CharacterManager()->CreateAutoROI(roiName, lodName, TRUE);

				if (roi != NULL) {
					roi->SetVisibility(FALSE);
				}

				delete[] lodName;
				delete[] roiName;
			}

			if (roi != NULL) {
				m_managedActors->Append(roi);
			}

			delete[] str;
		}
	}
}

// FUNCTION: LEGO1 0x100695c0
// FUNCTION: BETA10 0x1004f359
void LegoAnimPresenter::CreateSceneROIs()
{
	m_sceneROIs = new LegoROIList();

	if (m_sceneROIs) {
		const CompoundObject& rois = VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->GetROIs();
		LegoU32 numActors = m_anim->GetNumActors();

		for (LegoU32 i = 0; i < numActors; i++) {
			if (AppendROIToScene(rois, m_anim->GetActorName(i)) == FALSE) {
				LegoU32 actorType = m_anim->GetActorType(i);

				if (actorType == LegoAnimActorEntry::e_sceneRoi1 || actorType == LegoAnimActorEntry::e_sceneRoi2) {
					LegoChar lodName[256];
					const LegoChar* actorName = m_anim->GetActorName(i);

					LegoU32 len = strlen(actorName);
					strcpy(lodName, actorName);

					for (LegoChar* i = &lodName[len - 1]; isdigit(*i) || *i == '_'; i--) {
						*i = '\0';
					}

					strlwr(lodName);

					CharacterManager()->CreateAutoROI(actorName, lodName, FALSE);
					AppendROIToScene(rois, actorName);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100697c0
LegoChar* LegoAnimPresenter::GetVariableOrIdentity(const LegoChar* p_varName, const LegoChar* p_prefix)
{
	const LegoChar* str = p_varName;
	const char* var = VariableTable()->GetVariable(p_varName);

	if (*var) {
		str = var;
	}

	LegoU32 len = strlen(str) + (p_prefix ? strlen(p_prefix) : 0) + 2;
	LegoChar* result = new LegoChar[len];

	if (result != NULL) {
		*result = '\0';

		if (p_prefix) {
			strcpy(result, p_prefix);
			strcat(result, ":");
		}

		strcat(result, str);
	}

	return result;
}

// FUNCTION: LEGO1 0x100698b0
LegoBool LegoAnimPresenter::AppendROIToScene(const CompoundObject& p_rois, const LegoChar* p_varName)
{
	LegoBool result = FALSE;

	LegoChar* str;
	if (*(str = GetVariableOrIdentity(p_varName, NULL)) == '*') {
		LegoChar* tmp = GetActorName(str);
		delete[] str;
		str = tmp;
	}

	if (str != NULL && *str != '\0' && p_rois.size() > 0) {
		for (CompoundObject::const_iterator it = p_rois.begin(); it != p_rois.end(); it++) {
			LegoROI* roi = (LegoROI*) *it;
			const char* name = roi->GetName();

			if (name != NULL) {
				if (!strcmpi(name, str)) {
					m_sceneROIs->Append(roi);
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
LegoROI* LegoAnimPresenter::FindROI(const LegoChar* p_name)
{
	LegoROIListCursor cursor(m_sceneROIs);
	LegoROI* roi;

	while (cursor.Next(roi)) {
		LegoChar* nameOrVar = GetVariableOrIdentity(roi->GetName(), NULL);

		if (nameOrVar != NULL && !strcmpi(nameOrVar, p_name)) {
			delete[] nameOrVar;
			return roi;
		}

		delete[] nameOrVar;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10069b10
void LegoAnimPresenter::BuildROIMap()
{
	LegoAnimStructMap anims;

	if (m_ptAtCamROI != NULL) {
		memset(m_ptAtCamROI, 0, m_ptAtCamCount * sizeof(*m_ptAtCamROI));
	}

	UpdateStructMapAndROIIndex(anims, m_anim->GetRoot(), NULL);

	if (m_roiMap != NULL) {
		delete[] m_roiMap;
		m_roiMapSize = 0;
	}

	m_roiMapSize = 0;
	m_roiMap = new LegoROI*[anims.size() + 1];
	memset(m_roiMap, 0, (anims.size() + 1) * sizeof(*m_roiMap));

	for (LegoAnimStructMap::iterator it = anims.begin(); it != anims.end();) {
		MxU32 index = (*it).second.m_index;
		m_roiMap[index] = (*it).second.m_roi;

		if (m_roiMap[index]->GetName() != NULL) {
			for (MxS32 i = 0; i < m_ptAtCamCount; i++) {
				if (m_ptAtCamROI[i] == NULL && m_ptAtCamNames[i] != NULL) {
					if (!strcmpi(m_ptAtCamNames[i], m_roiMap[index]->GetName())) {
						m_ptAtCamROI[i] = m_roiMap[index];
						break;
					}
				}
			}
		}

		delete[] const_cast<char*>((*it).first);
		it++;
		m_roiMapSize++;
	}
}

// FUNCTION: LEGO1 0x1006a3c0
void LegoAnimPresenter::UpdateStructMapAndROIIndex(LegoAnimStructMap& p_map, LegoTreeNode* p_node, LegoROI* p_roi)
{
	LegoROI* roi = p_roi;
	LegoChar* und = NULL;
	LegoChar* und2 = NULL;
	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	const LegoChar* name = data->GetName();

	if (name != NULL && *name != '-') {
		if (*name == '*') {
			name = und2 = GetActorName(name);
		}

		und = GetVariableOrIdentity(name, p_roi != NULL ? p_roi->GetName() : NULL);

		if (p_roi == NULL) {
			roi = FindROI(und);

			if (roi != NULL) {
				UpdateStructMapAndROIIndexForNode(p_map, data, und, roi);
			}
			else {
				data->SetROIIndex(0);
			}
		}
		else {
			LegoROI* child = p_roi->FindChildROI(name, p_roi);

			if (child != NULL) {
				UpdateStructMapAndROIIndexForNode(p_map, data, und, child);
			}
			else {
				if (FindROI(name) != NULL) {
					UpdateStructMapAndROIIndex(p_map, p_node, NULL);
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
		UpdateStructMapAndROIIndex(p_map, p_node->GetChild(i), roi);
	}
}

// FUNCTION: LEGO1 0x1006a4f0
void LegoAnimPresenter::UpdateStructMapAndROIIndexForNode(
	LegoAnimStructMap& p_map,
	LegoAnimNodeData* p_data,
	const LegoChar* p_key,
	LegoROI* p_roi
)
{
	LegoAnimStructMap::iterator it;

	it = p_map.find(p_key);
	if (it == p_map.end()) {
		LegoAnimStruct animStruct;
		animStruct.m_index = p_map.size() + 1;
		animStruct.m_roi = p_roi;

		p_data->SetROIIndex(animStruct.m_index);

		LegoChar* key = new LegoChar[strlen(p_key) + 1];
		strcpy(key, p_key);

		p_map[key] = animStruct;
	}
	else {
		p_data->SetROIIndex((*it).second.m_index);
	}
}

// FUNCTION: LEGO1 0x1006aa60
// FUNCTION: BETA10 0x1004feee
void LegoAnimPresenter::ReleaseManagedActors()
{
	LegoROIListCursor cursor(m_managedActors);
	LegoROI* roi;

	while (cursor.Next(roi)) {
		const char* name = roi->GetName();

		if (m_localActors || !CharacterManager()->IsActor(name)) {
			CharacterManager()->ReleaseActor(name);
		}
	}
}

// FUNCTION: LEGO1 0x1006ab70
void LegoAnimPresenter::AppendManagedActors()
{
	if (m_localActors) {
		AnimationManager()->FUN_10063270(m_managedActors, this);
	}
	else {
		AnimationManager()->FUN_10063780(m_managedActors);
	}
}

// FUNCTION: LEGO1 0x1006aba0
LegoBool LegoAnimPresenter::VerifyAnimationTree()
{
	return VerifyAnimationNode(m_anim->GetRoot(), NULL);
}

// FUNCTION: LEGO1 0x1006abb0
MxBool LegoAnimPresenter::VerifyAnimationNode(LegoTreeNode* p_node, LegoROI* p_roi)
{
	MxBool result = FALSE;
	LegoROI* roi = p_roi;
	LegoChar* varOrName = NULL;
	const LegoChar* name = ((LegoAnimNodeData*) p_node->GetData())->GetName();
	MxS32 i, count;

	if (name != NULL && *name != '-') {
		varOrName = GetVariableOrIdentity(name, p_roi != NULL ? p_roi->GetName() : NULL);

		if (p_roi == NULL) {
			roi = FindROI(varOrName);

			if (roi == NULL) {
				goto done;
			}
		}
		else {
			LegoROI* child = p_roi->FindChildROI(name, p_roi);

			if (child == NULL) {
				if (FindROI(name) != NULL) {
					if (VerifyAnimationNode(p_node, NULL)) {
						result = TRUE;
					}
				}

				goto done;
			}
		}
	}

	count = p_node->GetNumChildren();
	for (i = 0; i < count; i++) {
		if (!VerifyAnimationNode(p_node->GetChild(i), roi)) {
			goto done;
		}
	}

	result = TRUE;

done:
	if (varOrName != NULL) {
		delete[] varOrName;
	}

	return result;
}

// FUNCTION: LEGO1 0x1006ac90
// FUNCTION: BETA10 0x1005022e
void LegoAnimPresenter::SubstituteVariables()
{
	if (m_substMap != NULL) {
		MxVariableTable* variableTable = VariableTable();

		for (LegoAnimSubstMap::iterator it = m_substMap->begin(); it != m_substMap->end(); it++) {
			variableTable->SetVariable((*it).first, (*it).second);
		}
	}
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

		ApplyTransformWithVisibilityAndCam(m_anim, time, m_transform);

		if (m_ptAtCamROI != NULL && m_currentWorld != NULL && m_currentWorld->GetCameraController() != NULL) {
			for (MxS32 i = 0; i < m_ptAtCamCount; i++) {
				if (m_ptAtCamROI[i] != NULL) {
					MxMatrix mat(m_ptAtCamROI[i]->GetLocal2World());

					Vector3 pos(mat[0]);
					Vector3 dir(mat[1]);
					Vector3 up(mat[2]);
					Vector3 und(mat[3]);

					float possqr = sqrt(pos.LenSquared());
					float dirsqr = sqrt(dir.LenSquared());
					float upsqr = sqrt(up.LenSquared());

					up = und;

					up -= m_currentWorld->GetCameraController()->GetWorldLocation();
					dir /= dirsqr;
					pos.EqualsCross(dir, up);
					pos.Unitize();
					up.EqualsCross(pos, dir);
					pos *= possqr;
					dir *= dirsqr;
					up *= upsqr;

					m_ptAtCamROI[i]->SetLocal2World(mat);
					m_ptAtCamROI[i]->WrappedUpdateWorldData();
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006afc0
// FUNCTION: BETA10 0x1005059a
MxResult LegoAnimPresenter::GetTransforms(MxMatrix*& p_matrix, float p_time)
{
	MxU32 length = m_roiMapSize + 1;
	p_matrix = new MxMatrix[length];

	MxS32 i;
	for (i = 1; i < length; i++) {
		if (m_roiMap[i] != NULL) {
			p_matrix[i] = m_roiMap[i]->GetLocal2World();
		}
	}

	ApplyTransform(m_anim, p_time, m_transform);

	for (i = 1; i < length; i++) {
		MxMatrix mat;

		if (m_roiMap[i] != NULL) {
			mat = p_matrix[i];
			p_matrix[i] = m_roiMap[i]->GetLocal2World();
			m_roiMap[i]->SetLocal2World(mat);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1006b140
// FUNCTION: BETA10 0x100507e0
MxResult LegoAnimPresenter::CopyTransform(LegoROI* p_roi)
{
	if (p_roi == NULL) {
		return FAILURE;
	}
#ifdef BETA10
	MxMatrix unused_matrix;
#endif

	Matrix4* mn = new MxMatrix();
	assert(mn);

	MxMatrix inverse;
	const Matrix4& local2world = p_roi->GetLocal2World();
	MxMatrix* roiTransforms;
	MxU32 i;

	if (GetTransforms(roiTransforms, 0.0f) != SUCCESS) {
		goto done;
	}

	for (i = 1; i <= m_roiMapSize; i++) {
		if (m_roiMap[i] == p_roi) {
			if (roiTransforms[i].Invert(inverse) != SUCCESS) {
				goto done;
			}

			break;
		}
	}

	{
		mn->Product(inverse, local2world);
		SetRoiTransform(mn);
		delete[] roiTransforms;
		SetRoiTransformApplied();

		MxMatrix originalTransform(*m_transform);
		MxMatrix newTransform;

		newTransform.Product(originalTransform, *m_roiTransform);
		*m_transform = newTransform;
		return SUCCESS;
	}

done:
	if (mn != NULL) {
		delete mn;
	}

	if (roiTransforms != NULL) {
		delete[] roiTransforms;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1006b550
// FUNCTION: BETA10 0x10050a9c
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
// FUNCTION: BETA10 0x10050b85
void LegoAnimPresenter::StartingTickle()
{
	SubstituteVariables();
	CreateManagedActors();
	CreateSceneROIs();

	if (m_flags & c_mustSucceed && !VerifyAnimationTree()) {
		goto done;
	}

	BuildROIMap();
	SetDisabled(TRUE);

	if (m_transform == NULL) {
		if (fabs(m_action->GetDirection()[0]) >= 0.00000047683716F ||
			fabs(m_action->GetDirection()[1]) >= 0.00000047683716F ||
			fabs(m_action->GetDirection()[2]) >= 0.00000047683716F) {
			m_transform = new MxMatrix();
			CalcLocalTransform(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp(), *m_transform);
		}
		else if (m_roiMap != NULL) {
			LegoROI* roi = m_roiMap[1];

			if (roi != NULL) {
				MxMatrix mat;
				mat = roi->GetLocal2World();
				m_transform = new MxMatrix(mat);
			}
		}
	}

	if ((m_action->GetDuration() == -1 || ((MxDSMediaAction*) m_action)->GetSustainTime() == -1) &&
		m_compositePresenter) {
		m_compositePresenter->AdvanceSerialAction(this);
	}
	else {
		m_action->SetTimeStarted(Timer()->GetTime());
	}

	ProgressTickleState(e_streaming);

	if (m_compositePresenter && m_compositePresenter->IsA("LegoAnimMMPresenter")) {
		m_localActors = ((LegoAnimMMPresenter*) m_compositePresenter)->FUN_1004b8b0();
		m_compositePresenter->AdvanceSerialAction(this);
	}

	AddToWorld();

done:
	if (m_sceneROIs != NULL) {
		delete m_sceneROIs;
		m_sceneROIs = NULL;
	}
}

// FUNCTION: LEGO1 0x1006b840
void LegoAnimPresenter::StreamingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_animationFinished) {
		ProgressTickleState(e_done);
		if (m_compositePresenter) {
			if (m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				m_compositePresenter->AdvanceSerialAction(this);
			}
		}
	}
	else {
		if (m_action->GetElapsedTime() > m_anim->GetDuration() + m_action->GetStartTime()) {
			m_animationFinished = TRUE;
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

// FUNCTION: LEGO1 0x1006b900
// FUNCTION: BETA10 0x100510d8
void LegoAnimPresenter::ApplyTransform(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix)
{
	LegoTreeNode* root = p_anim->GetRoot();
	MxMatrix mat;
	LegoAnimNodeData* data = (LegoAnimNodeData*) root->GetData();

	if (p_matrix != NULL) {
		mat = *p_matrix;
	}
	else {
		LegoROI* roi = m_roiMap[data->GetROIIndex()];

		if (roi != NULL) {
			mat = roi->GetLocal2World();
		}
		else {
			mat.SetIdentity();
		}
	}

	LegoROI::ApplyTransform(root, mat, p_time, m_roiMap);
}

// FUNCTION: LEGO1 0x1006b9a0
// FUNCTION: BETA10 0x1005118b
void LegoAnimPresenter::ApplyTransformWithVisibilityAndCam(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix)
{
	LegoTreeNode* root = p_anim->GetRoot();
	MxMatrix mat;
	LegoAnimNodeData* data = (LegoAnimNodeData*) root->GetData();

	if (p_matrix != NULL) {
		mat = *p_matrix;
	}
	else {
		LegoROI* roi = m_roiMap[data->GetROIIndex()];

		if (roi != NULL) {
			mat = roi->GetLocal2World();
		}
		else {
			mat.SetIdentity();
		}
	}

	if (p_anim->GetCamAnim() != NULL) {
		MxMatrix transform(mat);
		p_anim->GetCamAnim()->CalculateCameraTransform(p_time, transform);

		if (m_currentWorld != NULL && m_currentWorld->GetCameraController() != NULL) {
			m_currentWorld->GetCameraController()->TransformPointOfView(transform, FALSE);
		}
	}

	LegoROI::ApplyAnimationTransformation(root, mat, p_time, m_roiMap);
}

// FUNCTION: LEGO1 0x1006bac0
// FUNCTION: BETA10 0x100512e1
void LegoAnimPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength) {
		char extraCopy[256];
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		char output[256];
		if (KeyValueStringParse(NULL, g_strFROM_PARENT, extraCopy) && m_compositePresenter != NULL) {
			m_compositePresenter->GetAction()->GetExtra(extraLength, extraData);

			if (extraLength) {
				memcpy(extraCopy, extraData, extraLength);
				extraCopy[extraLength] = '\0';
			}
		}

		if (KeyValueStringParse(output, g_strHIDE_ON_STOP, extraCopy)) {
			m_flags |= c_hideOnStop;
		}

		if (KeyValueStringParse(output, g_strMUST_SUCCEED, extraCopy)) {
			m_flags |= c_mustSucceed;
		}

		if (KeyValueStringParse(output, g_strSUBST, extraCopy)) {
			m_substMap = new LegoAnimSubstMap();

			char* substToken = output;
			char *key, *value;

			while ((key = strtok(substToken, g_parseExtraTokens))) {
				substToken = NULL;

				if ((value = strtok(NULL, g_parseExtraTokens))) {
					char* keyCopy = new char[strlen(key) + 1];
					strcpy(keyCopy, key);
					char* valueCopy = new char[strlen(value) + 1];
					strcpy(valueCopy, value);
					(*m_substMap)[keyCopy] = valueCopy;
				}
			}
		}

		if (KeyValueStringParse(output, g_strWORLD, extraCopy)) {
			char* token = strtok(output, g_parseExtraTokens);
			m_worldAtom = MxAtomId(token, e_lowerCase2);

			token = strtok(NULL, g_parseExtraTokens);
			m_worldId = atoi(token);
		}

		if (KeyValueStringParse(output, g_strPTATCAM, extraCopy)) {
			list<char*> tokens;

			if (m_ptAtCamNames != NULL) {
				for (MxS32 i = 0; i < m_ptAtCamCount; i++) {
					if (m_ptAtCamNames[i] != NULL) {
						// (modernization) critical bug: wrong free
						delete[] m_ptAtCamNames;
					}
				}

				delete[] m_ptAtCamNames;
				m_ptAtCamNames = NULL;
			}

			if (m_ptAtCamROI != NULL) {
				delete[] m_ptAtCamROI;
				m_ptAtCamROI = NULL;
			}

			char* token = strtok(output, g_parseExtraTokens);
			while (token != NULL) {
				char* valueCopy = new char[strlen(token) + 1];
				strcpy(valueCopy, token);
				tokens.push_back(valueCopy);
				token = strtok(NULL, g_parseExtraTokens);
			}

			m_ptAtCamCount = tokens.size();
			if (m_ptAtCamCount != 0) {
				m_ptAtCamROI = new LegoROI*[m_ptAtCamCount];
				m_ptAtCamNames = new char*[m_ptAtCamCount];
				memset(m_ptAtCamROI, 0, sizeof(*m_ptAtCamROI) * m_ptAtCamCount);
				memset(m_ptAtCamNames, 0, sizeof(*m_ptAtCamNames) * m_ptAtCamCount);

				MxS32 i = 0;
				for (list<char*>::iterator it = tokens.begin(); it != tokens.end(); it++, i++) {
					m_ptAtCamNames[i] = *it;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006c570
// FUNCTION: BETA10 0x10051ab3
void LegoAnimPresenter::SetTransform(Matrix4& p_matrix)
{
	if (m_transform != NULL) {
		delete m_transform;
	}

	m_transform = new MxMatrix(p_matrix);
}

// FUNCTION: LEGO1 0x1006c620
MxResult LegoAnimPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxVideoPresenter::StartAction(p_controller, p_action);
	m_displayZ = 0;
	return result;
}

// FUNCTION: LEGO1 0x1006c640
// FUNCTION: BETA10 0x10051b7a
void LegoAnimPresenter::EndAction()
{
	undefined4 unused; // required for match

	if (m_action == NULL) {
		return;
	}

	LegoWorld* world = CurrentWorld();

	if (world != NULL) {
		LegoEndAnimNotificationParam param(c_notificationEndAnim, NULL, 0);
		NotificationManager()->Send(world, param);
	}

	if (m_anim != NULL) {
		ApplyTransformWithVisibilityAndCam(m_anim, m_anim->GetDuration(), m_transform);
	}

	if (m_roiMapSize != 0 && m_roiMap != NULL && m_roiMap[1] != NULL && m_flags & c_hideOnStop) {
		for (MxS16 i = 1; i <= m_roiMapSize; i++) {
			if (m_roiMap[i] != NULL) {
				m_roiMap[i]->SetVisibility(FALSE);
			}
		}
	}

	SetDisabled(FALSE);
	AppendManagedActors();
	RemoveFromWorld();

	if (m_currentWorld != NULL) {
		m_currentWorld->Remove(this);
	}

	MxVideoPresenter::EndAction();
}

// FUNCTION: LEGO1 0x1006c7a0
// FUNCTION: BETA10 0x10051da6
void LegoAnimPresenter::ApplyFinishedTransform()
{
	if (m_anim != NULL) {
		ApplyTransformWithVisibilityAndCam(m_anim, m_anim->GetDuration(), m_transform);
	}

	m_animationFinished = TRUE;
}

// FUNCTION: LEGO1 0x1006c7d0
// FUNCTION: BETA10 0x10051e07
void LegoAnimPresenter::AddToWorld()
{
	if (m_transform) {
		m_centerPoint += (*m_transform)[3];
	}
	else {
		m_centerPoint += m_action->GetLocation();
	}

	if (m_currentWorld == NULL) {
		m_currentWorld = m_worldId != -1 ? FindWorld(m_worldAtom, m_worldId) : CurrentWorld();
	}

	if (m_currentWorld) {
		m_currentWorld->AddPresenterIfInRange(this);
		if (!m_compositePresenter || !m_compositePresenter->IsA("LegoAnimMMPresenter")) {
			m_currentWorld->Add(this);
		}
	}
}

// FUNCTION: LEGO1 0x1006c860
// FUNCTION: BETA10 0x10051f45
void LegoAnimPresenter::RemoveFromWorld()
{
	if (m_currentWorld != NULL) {
		m_currentWorld->RemovePresenterFromBoundaries(this);

		if (m_compositePresenter != NULL && m_compositePresenter->IsA("LegoAnimMMPresenter")) {
			return;
		}

		m_currentWorld->Remove(this);
	}
}

// FUNCTION: LEGO1 0x1006c8a0
void LegoAnimPresenter::SetDisabled(MxBool p_disabled)
{
	if (m_roiMapSize != 0 && m_roiMap != NULL) {
		for (MxU32 i = 1; i <= m_roiMapSize; i++) {
			LegoEntity* entity = m_roiMap[i]->GetEntity();

			if (entity != NULL) {
				if (p_disabled) {
					entity->SetInteractionFlag(LegoEntity::c_disabled);
				}
				else {
					entity->ClearInteractionFlag(LegoEntity::c_disabled);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006c8f0
// FUNCTION: BETA10 0x1005206c
MxU32 LegoAnimPresenter::Intersect(
	Vector3& p_rayOrigin,
	Vector3& p_rayDirection,
	float p_rayLength,
	float p_radius,
	Vector3& p_intersectionPoint
)
{
	Mx3DPointFloat centerToRay, rayEnd;

	rayEnd = p_rayDirection;
	rayEnd *= p_rayLength;
	rayEnd += p_rayOrigin;

	centerToRay = rayEnd;
	centerToRay -= m_centerPoint;

	float len = centerToRay.LenSquared();
	if (len <= 0.0f) {
		return TRUE;
	}

	len = sqrt(len);
	if (len <= m_boundingRadius + p_radius && m_roiMapSize != 0 && m_roiMap != NULL) {
		for (MxU32 i = 1; i <= m_roiMapSize; i++) {
			if (m_roiMap[i]->GetLODCount() != 0 &&
				m_roiMap[i]
					->Intersect(p_rayOrigin, p_rayDirection, p_rayLength, p_radius, p_intersectionPoint, FALSE)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1006ca50
// FUNCTION: BETA10 0x100521d0
MxResult LegoAnimPresenter::AddActors(LegoPathBoundary* p_boundary)
{
	for (MxU32 i = 1; i <= m_roiMapSize; i++) {
		LegoEntity* entity = m_roiMap[i]->GetEntity();

		if (entity != NULL) {
			p_boundary->AddActor((LegoPathActor*) entity);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1006caa0
// FUNCTION: BETA10 0x1005223d
void LegoLoopingAnimPresenter::StreamingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_animationFinished) {
		ProgressTickleState(e_done);
		if (m_compositePresenter) {
			if (m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				m_compositePresenter->AdvanceSerialAction(this);
			}
		}
	}
	else {
		if (m_action->GetDuration() != -1) {
			if (m_action->GetElapsedTime() > m_action->GetDuration() + m_action->GetStartTime()) {
				m_animationFinished = TRUE;
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006cb40
// FUNCTION: BETA10 0x1005239a
void LegoLoopingAnimPresenter::PutFrame()
{
	MxLong time;

	if (m_action->GetStartTime() <= m_action->GetElapsedTime()) {
		time = (m_action->GetElapsedTime() - m_action->GetStartTime()) % m_anim->GetDuration();
	}
	else {
		time = 0;
	}

	ApplyTransformWithVisibilityAndCam(m_anim, time, m_transform);

	if (m_ptAtCamROI != NULL && m_currentWorld != NULL && m_currentWorld->GetCameraController() != NULL) {
		for (MxS32 i = 0; i < m_ptAtCamCount; i++) {
			if (m_ptAtCamROI[i] != NULL) {
				MxMatrix mat(m_ptAtCamROI[i]->GetLocal2World());

				Vector3 pos(mat[0]);
				Vector3 dir(mat[1]);
				Vector3 up(mat[2]);
				Vector3 und(mat[3]);

				float possqr = sqrt(pos.LenSquared());
				float dirsqr = sqrt(dir.LenSquared());
				float upsqr = sqrt(up.LenSquared());

				up = und;

				up -= m_currentWorld->GetCameraController()->GetWorldLocation();
				dir /= dirsqr;
				pos.EqualsCross(dir, up);
				pos.Unitize();
				up.EqualsCross(pos, dir);
				pos *= possqr;
				dir *= dirsqr;
				up *= upsqr;

				m_ptAtCamROI[i]->SetLocal2World(mat);
				m_ptAtCamROI[i]->WrappedUpdateWorldData();
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006cdd0
LegoLocomotionAnimPresenter::LegoLocomotionAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1006d050
LegoLocomotionAnimPresenter::~LegoLocomotionAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1006d0b0
void LegoLocomotionAnimPresenter::Init()
{
	m_unk0xc0 = 0;
	m_unk0xc4 = NULL;
	m_unk0xcc = -1;
	m_unk0xd0 = -1;
	m_roiMapList = NULL;
	m_worldRefCounter = 0;
}

// FUNCTION: LEGO1 0x1006d0e0
void LegoLocomotionAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);

	if (m_unk0xc4) {
		delete[] m_unk0xc4;
	}

	if (m_roiMapList) {
		delete m_roiMapList;
	}

	m_roiMap = NULL;
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		LegoLoopingAnimPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x1006d140
MxResult LegoLocomotionAnimPresenter::CreateAnim(MxStreamChunk* p_chunk)
{
	MxResult result = LegoAnimPresenter::CreateAnim(p_chunk);
	return result == SUCCESS ? SUCCESS : result;
}

// FUNCTION: LEGO1 0x1006d160
// FUNCTION: BETA10 0x100528c7
MxResult LegoLocomotionAnimPresenter::AddToManager()
{
	m_roiMapList = new LegoROIMapList();

	if (m_roiMapList == NULL) {
		return FAILURE;
	}

	return LegoAnimPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006d5b0
void LegoLocomotionAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1006d5c0
void LegoLocomotionAnimPresenter::PutFrame()
{
	// Empty
}

// FUNCTION: LEGO1 0x1006d5d0
void LegoLocomotionAnimPresenter::ReadyTickle()
{
	LegoLoopingAnimPresenter::ReadyTickle();

	if (m_currentWorld != NULL && m_currentTickleState == e_starting) {
		m_currentWorld->Add(this);
		if (m_compositePresenter != NULL) {
			SendToCompositePresenter(Lego());
		}

		m_worldRefCounter++;
	}
}

// FUNCTION: LEGO1 0x1006d610
// FUNCTION: BETA10 0x10052a34
void LegoLocomotionAnimPresenter::StartingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_roiMapList->GetNumElements() != 0) {
		ProgressTickleState(e_streaming);
	}
}

// FUNCTION: LEGO1 0x1006d660
void LegoLocomotionAnimPresenter::StreamingTickle()
{
	if (m_worldRefCounter == 0) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x1006d670
void LegoLocomotionAnimPresenter::EndAction()
{
	if (m_action) {
		MxVideoPresenter::EndAction();
	}
}

// FUNCTION: LEGO1 0x1006d680
// FUNCTION: BETA10 0x10052b3d
void LegoLocomotionAnimPresenter::CreateROIAndBuildMap(LegoAnimActor* p_actor, MxFloat p_worldSpeed)
{
	// This asserts that LegoLocomotionAnimPresenter is contained in legoanimpresenter.cpp
	AUTOLOCK(m_criticalSection);

	MxVariableTable* variableTable = VariableTable();

	const char* key = ((LegoAnimNodeData*) m_anim->GetRoot()->GetData())->GetName();
	variableTable->SetVariable(key, p_actor->GetROI()->GetName());

	CreateSceneROIs();
	BuildROIMap();

	if (m_roiMap != NULL) {
		m_roiMapList->Append(m_roiMap);
		p_actor->CreateAnimActorStruct(m_anim, p_worldSpeed, m_roiMap, m_roiMapSize);
		m_roiMap = NULL;
	}

	variableTable->SetVariable(key, "");

	if (m_sceneROIs != NULL) {
		delete m_sceneROIs;
		m_sceneROIs = NULL;
	}
}

// We do not have any hard evidence that `LegoHideAnimPresenter` is part of this file as well.
// However, since all of the other AnimPresenters are in the same file, it is reasonable to assume
// that the same holds here.

// FUNCTION: LEGO1 0x1006d7e0
LegoHideAnimPresenter::LegoHideAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1006d9f0
LegoHideAnimPresenter::~LegoHideAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1006da50
void LegoHideAnimPresenter::Init()
{
	m_boundaryMap = NULL;
}

// FUNCTION: LEGO1 0x1006da60
void LegoHideAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);

	if (m_boundaryMap) {
		delete[] m_boundaryMap;
	}
	Init();

	m_criticalSection.Leave();

	// This appears to be a bug, since it results in an endless loop
	if (!p_fromDestructor) {
		LegoHideAnimPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x1006dab0
MxResult LegoHideAnimPresenter::AddToManager()
{
	return LegoAnimPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006dac0
void LegoHideAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1006dad0
void LegoHideAnimPresenter::PutFrame()
{
}

// FUNCTION: LEGO1 0x1006dae0
// FUNCTION: BETA10 0x100530f4
void LegoHideAnimPresenter::ReadyTickle()
{
	LegoLoopingAnimPresenter::ReadyTickle();

	if (m_currentWorld) {
		if (m_currentTickleState == e_starting && m_compositePresenter != NULL) {
			SendToCompositePresenter(Lego());
		}

		m_currentWorld->Add(this);
	}
}

// FUNCTION: LEGO1 0x1006db20
// FUNCTION: BETA10 0x1005316b
void LegoHideAnimPresenter::StartingTickle()
{
	LegoLoopingAnimPresenter::StartingTickle();

	if (m_currentTickleState == e_streaming) {
		AssignIndiciesWithMap();
		ApplyVisibility(0);
	}
}

// FUNCTION: LEGO1 0x1006db40
// FUNCTION: BETA10 0x100531ab
void LegoHideAnimPresenter::ApplyVisibility(LegoTime p_time)
{
	ApplyVisibility(m_anim->GetRoot(), p_time);
}

// FUNCTION: LEGO1 0x1006db60
// FUNCTION: BETA10 0x100531de
void LegoHideAnimPresenter::ApplyVisibility(LegoTreeNode* p_node, LegoTime p_time)
{
	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	MxBool newB = FALSE;
	MxBool previousB = FALSE;

	if (m_roiMap != NULL) {
		LegoROI* roi = m_roiMap[data->GetROIIndex()];

		if (roi != NULL) {
			newB = data->GetVisibility(p_time);
			previousB = roi->GetVisibility();
			roi->SetVisibility(newB);
		}
	}

	if (m_boundaryMap != NULL) {
		LegoPathBoundary* boundary = m_boundaryMap[data->GetBoundaryIndex()];

		if (boundary != NULL) {
			newB = data->GetVisibility(p_time);
			previousB = boundary->GetVisibility();
			boundary->SetVisibility(newB);
		}
	}

	for (MxS32 i = 0; i < p_node->GetNumChildren(); i++) {
		ApplyVisibility(p_node->GetChild(i), p_time);
	}
}

// FUNCTION: LEGO1 0x1006dc10
// FUNCTION: BETA10 0x100532fd
void LegoHideAnimPresenter::AssignIndiciesWithMap()
{
	LegoHideAnimStructMap anims;

	BuildMap(anims, m_anim->GetRoot());

	if (m_boundaryMap != NULL) {
		delete[] m_boundaryMap;
	}

	m_boundaryMap = new LegoPathBoundary*[anims.size() + 1];
	m_boundaryMap[0] = NULL;

	for (LegoHideAnimStructMap::iterator it = anims.begin(); !(it == anims.end()); it++) {
		m_boundaryMap[(*it).second.m_index] = (*it).second.m_boundary;
		delete[] const_cast<char*>((*it).first);
	}
}

// FUNCTION: LEGO1 0x1006e3f0
// FUNCTION: BETA10 0x1005345e
void LegoHideAnimPresenter::BuildMap(LegoHideAnimStructMap& p_map, LegoTreeNode* p_node)
{
	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	const char* name = data->GetName();

	if (name != NULL) {
		LegoPathBoundary* boundary = m_currentWorld->FindPathBoundary(name);

		if (boundary != NULL) {
			CheckedAdd(p_map, data, name, boundary);
		}
		else {
			data->SetBoundaryIndex(0);
		}
	}

	MxS32 count = p_node->GetNumChildren();
	for (MxS32 i = 0; i < count; i++) {
		BuildMap(p_map, p_node->GetChild(i));
	}
}

// FUNCTION: LEGO1 0x1006e470
// FUNCTION: BETA10 0x10053520
void LegoHideAnimPresenter::CheckedAdd(
	LegoHideAnimStructMap& p_map,
	LegoAnimNodeData* p_data,
	const char* p_name,
	LegoPathBoundary* p_boundary
)
{
	LegoHideAnimStructMap::iterator it;

	it = p_map.find(p_name);
	if (it == p_map.end()) {
		LegoHideAnimStruct animStruct;
		animStruct.m_index = p_map.size() + 1;
		animStruct.m_boundary = p_boundary;

		p_data->SetBoundaryIndex(animStruct.m_index);

		char* name = new char[strlen(p_name) + 1];
		strcpy(name, p_name);

		p_map[name] = animStruct;
	}
	else {
		p_data->SetBoundaryIndex((*it).second.m_index);
	}
}

// FUNCTION: LEGO1 0x1006e9e0
// FUNCTION: BETA10 0x100535ef
void LegoHideAnimPresenter::EndAction()
{
	if (m_action) {
		MxVideoPresenter::EndAction();

		if (m_currentWorld) {
			m_currentWorld->Remove(this);
		}
	}
}
