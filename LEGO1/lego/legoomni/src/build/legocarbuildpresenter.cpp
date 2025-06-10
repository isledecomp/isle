#include "legocarbuildpresenter.h"

#include "3dmanager/lego3dmanager.h"
#include "legocarbuild.h"
#include "legoentity.h"
#include "legogamestate.h"
#include "legomain.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legoutil.h"
#include "mxautolock.h"
#include "mxcompositepresenter.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "realtime/realtime.h"

DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter::UnknownListEntry, 0x0c)
DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter, 0x150)

// FUNCTION: LEGO1 0x10078400
// FUNCTION: BETA10 0x100707c0
LegoCarBuildAnimPresenter::LegoCarBuildAnimPresenter()
{
	m_shelfState = e_selected;
	m_numberOfParts = 0;
	m_placedPartCount = 0;
	m_parts = NULL;
	m_platformAnimNodeData = NULL;
	m_shelfFrame = 0;
	m_shelfFrameBuffer = 0;
	m_shelfFrameMax = 0;
	m_shelfFrameInterval = 0;
	m_unk0x13c = 0;
	m_carBuildEntity = NULL;
	m_unk0x144 = -1;
	m_unk0x148 = -1;
	m_mainSourceId = NULL;
}

// FUNCTION: LEGO1 0x10078680
// FUNCTION: BETA10 0x1007091e
LegoCarBuildAnimPresenter::~LegoCarBuildAnimPresenter()
{
	if (m_parts) {
		for (MxS16 i = 0; i < m_numberOfParts; i++) {
			delete[] m_parts[i].m_name;
			delete[] m_parts[i].m_wiredName;
		}
		delete[] m_parts;
	}

	m_platformAnim.GetRoot()->SetNumChildren(0);
	*m_platformAnim.GetRoot()->GetChildren() = NULL;

	if (m_mainSourceId) {
		delete[] m_mainSourceId;
	}
}

// FUNCTION: BETA10 0x100733d0
inline void LegoCarBuildAnimPresenter::Beta10Inline0x100733d0()
{
	MxLong time = Timer()->GetTime();
	MxLong bvar5;

	if (m_unk0x13c < time) {
		bvar5 = FALSE;

		// I have no idea why this conditional is so convoluted
		if (m_unk0x13c & c_bit1) {
			bvar5 = TRUE;
			m_unk0x13c = time + 400;
		}
		else {
			m_unk0x13c = time + 200;
		}

		if (bvar5) {
			m_unk0x13c &= ~c_bit1;
		}
		else {
			m_unk0x13c |= c_bit1;
		}

		if (m_placedPartCount < m_numberOfParts) {

			const LegoChar* wiredName = m_parts[m_placedPartCount].m_wiredName;

			if (wiredName) {
				for (MxS32 i = 1; i <= m_roiMapSize; i++) {
					LegoROI* roi = m_roiMap[i];

					if (roi) {
						const LegoChar* name = roi->GetName();

						if (name && stricmp(wiredName, name) == 0) {
							if (bvar5) {
								roi->SetVisibility(TRUE);
							}
							else {
								roi->SetVisibility(FALSE);
							}
						}
					}
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10078790
// FUNCTION: BETA10 0x10070ab1
void LegoCarBuildAnimPresenter::PutFrame()
{
	switch (m_shelfState) {
	case e_selected:
		break;
	case e_moving:
		MoveShelfForward();
	case e_stopped:
		if (m_carBuildEntity->GetROI()) {
			FUN_1006b9a0(m_anim, m_shelfFrameBuffer, NULL);
		}
	default:
		break;
	}

	Beta10Inline0x100733d0();
}

// FUNCTION: LEGO1 0x100788c0
// FUNCTION: BETA10 0x10070b56
void LegoCarBuildAnimPresenter::ReadyTickle()
{
	if (!m_anim) {
		LegoAnimPresenter::ReadyTickle();

		if (!m_currentWorld) {
			return;
		}

#ifndef BETA10
		if (!m_anim) {
			return;
		}
#else
		assert(m_anim);
#endif
	}

	m_carBuildEntity = (LegoEntity*) m_currentWorld->Find("MxEntity", "Dunebld");

	if (!m_carBuildEntity) {
		m_carBuildEntity = (LegoEntity*) m_currentWorld->Find("MxEntity", "Chptrbld");
	}

	if (!m_carBuildEntity) {
		m_carBuildEntity = (LegoEntity*) m_currentWorld->Find("MxEntity", "Jetbld");
	}

	if (!m_carBuildEntity) {
		m_carBuildEntity = (LegoEntity*) m_currentWorld->Find("MxEntity", "bldrace");
	}

	if (m_carBuildEntity) {
		((LegoCarBuild*) m_currentWorld)->SetCarBuildAnimPresenter(this);
		m_placedPartCount = ((LegoCarBuild*) m_currentWorld)->GetPlacedPartCount();
		SetShelfState(e_stopped);
		m_previousTickleStates |= 1 << m_currentTickleState;
		m_currentTickleState = e_starting;
		m_compositePresenter->SendToCompositePresenter(Lego());
	}
	else {
		m_previousTickleStates |= 1 << m_currentTickleState;
		m_currentTickleState = e_ready;
	}
}

// FUNCTION: LEGO1 0x100789e0
// FUNCTION: BETA10 0x10070cdd
void LegoCarBuildAnimPresenter::StreamingTickle()
{
	if (!m_carBuildEntity->GetROI()) {
		return;
	}

	m_mainSourceId = new LegoChar[strlen(m_action->GetAtomId().GetInternal()) + 1];
	assert(m_mainSourceId);

	strcpy(m_mainSourceId, m_action->GetAtomId().GetInternal());
	m_mainSourceId[strlen(m_mainSourceId) - 1] = 'M';

	FUN_10079160();

	if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
		m_placedPartCount = 10;
	}

	MxS16 i;

	for (i = 0; i < m_numberOfParts; i++) {
		if (m_placedPartCount == i) {
			FUN_10079680(m_parts[i].m_wiredName);
		}
		else {
			FUN_100795d0(m_parts[i].m_wiredName);
		}

		if (i < m_placedPartCount) {
			FUN_10079050(i);
			FUN_10079680(m_parts[i].m_name);
		}

		LegoChar* name = m_parts[i].m_wiredName;

		if (name) {
			for (MxS32 j = 0; j <= m_roiMapSize; j++) {
				LegoROI* roi = m_roiMap[j];

				if (roi && roi->GetName() && (strcmpi(name, roi->GetName()) == 0)) {
					roi->ClearMeshOffset();
					roi->SetLodColor("lego red");
				}
			}
		}
	}

	LegoVideoManager* videoManager = VideoManager();
	assert(videoManager); // verifies variable name 'videoManager'

	Lego3DView* lego3dview = videoManager->Get3DManager()->GetLego3DView();
	LegoROI* videoManagerROI = videoManager->GetViewROI();
	LegoROI* local60 = m_carBuildEntity->GetROI();
	LegoROI* camera = NULL;
	MxFloat fov;

	MxS16 totalNodes = CountTotalTreeNodes(m_anim->GetRoot());

	for (i = 0; i < totalNodes; i++) {
		LegoAnimNodeData* animNodeData = (LegoAnimNodeData*) GetTreeNode(m_anim->GetRoot(), i)->GetData();

		if (strnicmp(animNodeData->GetName(), "CAM", strlen("CAM")) == 0) {
			camera = local60->FindChildROI(animNodeData->GetName(), local60);
			fov = atof(&animNodeData->GetName()[strlen(animNodeData->GetName()) - 2]);
			break;
		}
	}

	assert(camera); // verifies variable name 'camera'

	LegoROI* targetROI = local60->FindChildROI("TARGET", local60);

	Mx3DPointFloat dirVec;

	const Vector3 cameraPosition(camera->GetWorldPosition());
	const Vector3 upVec(camera->GetWorldUp());
	const Vector3 targetPosition(targetROI->GetWorldPosition());

	MxMatrix localTransform;

	dirVec[0] = targetPosition[0] - cameraPosition[0];
	dirVec[1] = targetPosition[1] - cameraPosition[1];
	dirVec[2] = targetPosition[2] - cameraPosition[2];
	dirVec.Unitize();

	CalcLocalTransform(cameraPosition, dirVec, upVec, localTransform);

	videoManagerROI->WrappedSetLocal2WorldWithWorldDataUpdate(localTransform);
	lego3dview->Moved(*videoManagerROI);
	videoManager->Get3DManager()->SetFrustrum(fov, 0.1, 250.0);

	m_buildViewMatrix = local60->FindChildROI("VIEW", local60)->GetLocal2World();

	m_previousTickleStates |= 1 << m_currentTickleState;
	m_currentTickleState = e_repeating;
}

// FUNCTION: LEGO1 0x10078db0
// FUNCTION: BETA10 0x100712f3
void LegoCarBuildAnimPresenter::EndAction()
{
	if (m_action) {
		AUTOLOCK(m_criticalSection);
		MxVideoPresenter::EndAction();
		m_shelfState = e_selected;
	}
}

// FUNCTION: LEGO1 0x10078e30
// FUNCTION: BETA10 0x10071387
MxResult LegoCarBuildAnimPresenter::Serialize(LegoStorage* p_storage)
{
	if (p_storage->IsReadMode()) {
		p_storage->ReadS16(m_placedPartCount);
		p_storage->ReadFloat(m_shelfFrame);
		for (MxS16 i = 0; i < m_numberOfParts; i++) {
			p_storage->ReadString(m_parts[i].m_name);
			p_storage->ReadString(m_parts[i].m_wiredName);
			p_storage->ReadS16(m_parts[i].m_objectId);
		}
	}
	else if (p_storage->IsWriteMode()) {
		p_storage->WriteS16(m_placedPartCount);
		p_storage->WriteFloat(m_shelfFrame);
		for (MxS16 i = 0; i < m_numberOfParts; i++) {
			p_storage->WriteString(m_parts[i].m_name);
			p_storage->WriteString(m_parts[i].m_wiredName);
			p_storage->WriteS16(m_parts[i].m_objectId);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10079050
// FUNCTION: BETA10 0x1007151e
void LegoCarBuildAnimPresenter::FUN_10079050(MxS16 p_index)
{
	SwapNodesByName(m_parts[p_index].m_wiredName, m_parts[p_index].m_name);
	FUN_100795d0(m_parts[p_index].m_wiredName);
}

// FUNCTION: LEGO1 0x10079090
// FUNCTION: BETA10 0x10071584
void LegoCarBuildAnimPresenter::SwapNodesByName(LegoChar* p_name1, LegoChar* p_name2)
{
	char buffer[40];

	if (stricmp(p_name1, p_name2) != 0) {
		LegoAnimNodeData* node1 = FindNodeDataByName(m_anim->GetRoot(), p_name1);
		LegoAnimNodeData* node2 = FindNodeDataByName(m_anim->GetRoot(), p_name2);

		strcpy(buffer, node1->GetName());
		strcpy(node1->GetName(), node2->GetName());
		strcpy(node2->GetName(), buffer);

		LegoU16 val1 = node1->GetUnknown0x20();
		node1->SetUnknown0x20(node2->GetUnknown0x20());
		node2->SetUnknown0x20(val1);
	}
}

// FUNCTION: LEGO1 0x10079160
// FUNCTION: BETA10 0x1007165d
void LegoCarBuildAnimPresenter::FUN_10079160()
{
	LegoTreeNode* root;
	LegoAnimNodeData* data2;
	MxS16 i;
	MxS16 totalNodes = CountTotalTreeNodes(m_anim->GetRoot());
	LegoChar* name;
	LegoTreeNode* destNode;
	LegoAnimNodeData* destData;
	LegoTreeNode** children;

	for (i = 0; i < totalNodes; i++) {
		LegoAnimNodeData* data = (LegoAnimNodeData*) GetTreeNode(m_anim->GetRoot(), i)->GetData();
		name = data->GetName();

		if (StringEqualsPlatform(name)) {
			m_platformAnimNodeData = data;
			if (m_platformAnimNodeData->GetNumRotationKeys() == 0) {
				LegoRotationKey* key = new LegoRotationKey();
				m_platformAnimNodeData->SetNumRotationKeys(1);
				m_platformAnimNodeData->SetRotationKeys(key);
			}
		}
		else {
			if (StringEndsOnYOrN(name)) {
				m_numberOfParts++;
			}
			else {
				if (m_shelfFrameMax == 0.0f && StringEqualsShelf(name)) {
					m_shelfFrameMax = m_anim->GetDuration();
					m_shelfFrameInterval = m_shelfFrameMax / (data->GetNumTranslationKeys() - 1);
				}
			}
		}
	}

	assert(m_numberOfParts);
	m_parts = new UnknownListEntry[m_numberOfParts];
	assert(m_parts);

	for (i = 0; i < totalNodes; i++) {
		name = ((LegoAnimNodeData*) GetTreeNode(m_anim->GetRoot(), i)->GetData())->GetName();

		strupr(name);

		if (StringEndsOnW(name)) {
			m_parts[name[strlen(name) - 1] - 'A'].m_wiredName = new LegoChar[strlen(name) + 1];

			// clang-format off
			assert(m_parts[name[strlen(name)-1] - 'A'].m_wiredName);
			// clang-format on

			strcpy(m_parts[name[strlen(name) - 1] - 'A'].m_wiredName, name);
		}
	}

	MxS16 counter = 0;

	for (i = 0; i < totalNodes; i++) {
		name = ((LegoAnimNodeData*) GetTreeNode(m_anim->GetRoot(), i)->GetData())->GetName();
		if (StringEndsOnYOrN(name)) {
			for (MxS16 ii = 0; ii < m_numberOfParts; ii++) {
				if (strnicmp(m_parts[ii].m_wiredName, name, strlen(name) - 2) == 0) {
					m_parts[ii].m_name = new LegoChar[strlen(name) + 1];
					assert(m_parts[ii].m_name);
					strcpy(m_parts[ii].m_name, name);

					counter++;
					if (m_numberOfParts == counter) {
						break;
					}
				}
			}
		}
	}

	destNode = new LegoTreeNode();
	assert(destNode);
	destData = new LegoAnimNodeData();
	assert(destData);
	destNode->SetData(destData);

	root = m_anim->GetRoot();
	data2 = (LegoAnimNodeData*) root->GetData();
	destData->SetName(data2->GetName());

	destNode->SetNumChildren(1);
	children = new LegoTreeNode*[1];
	assert(children);
	*children = FindNodeByName(m_anim->GetRoot(), "PLATFORM");

	destNode->SetChildren(children);
	m_platformAnim.SetRoot(destNode);
}

// FUNCTION: LEGO1 0x100795d0
// FUNCTION: BETA10 0x10071d96
void LegoCarBuildAnimPresenter::FUN_100795d0(LegoChar* p_param)
{
	LegoAnimNodeData* data = FindNodeDataByName(m_anim->GetRoot(), p_param);

	if (data) {
		LegoMorphKey* oldMorphKeys = data->GetMorphKeys();

		LegoMorphKey* newHideKey = new LegoMorphKey();
		assert(newHideKey);

		newHideKey->SetTime(0);
		newHideKey->SetUnknown0x08(FALSE);

		data->SetNumMorphKeys(1);
		data->SetMorphKeys(newHideKey);

		delete[] oldMorphKeys;
	}
}

// FUNCTION: LEGO1 0x10079680
// FUNCTION: BETA10 0x10071ec5
void LegoCarBuildAnimPresenter::FUN_10079680(LegoChar* p_param)
{
	LegoAnimNodeData* data = FindNodeDataByName(m_anim->GetRoot(), p_param);

	if (data) {
		LegoMorphKey* oldMorphKeys = data->GetMorphKeys();

		data->SetNumMorphKeys(0);
		data->SetMorphKeys(NULL);

		delete[] oldMorphKeys;
	}
}

// FUNCTION: LEGO1 0x100796b0
// FUNCTION: BETA10 0x10071f3c
LegoAnimNodeData* LegoCarBuildAnimPresenter::FindNodeDataByName(LegoTreeNode* p_treeNode, const LegoChar* p_name)
{
	LegoAnimNodeData* data = NULL;

	if (p_treeNode) {
		data = (LegoAnimNodeData*) p_treeNode->GetData();

		if (stricmp(data->GetName(), p_name) == 0) {
			return data;
		}

		for (MxS32 i = 0; i < p_treeNode->GetNumChildren(); i++) {
			data = FindNodeDataByName(p_treeNode->GetChildren()[i], p_name);

			if (data) {
				return data;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10079720
// FUNCTION: BETA10 0x10071fec
LegoTreeNode* LegoCarBuildAnimPresenter::FindNodeByName(LegoTreeNode* p_treeNode, const LegoChar* p_name)
{
	LegoAnimNodeData* data = NULL;
	LegoTreeNode* node = NULL;

	if (p_treeNode) {
		data = (LegoAnimNodeData*) p_treeNode->GetData();

		if (stricmp(data->GetName(), p_name) == 0) {
			return p_treeNode;
		}

		for (MxS32 i = 0; i < p_treeNode->GetNumChildren(); i++) {
			node = FindNodeByName(p_treeNode->GetChildren()[i], p_name);

			if (node) {
				return node;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10079790
// FUNCTION: BETA10 0x100720a3
void LegoCarBuildAnimPresenter::FUN_10079790(const LegoChar* p_name)
{
	MxS16 i;
	LegoChar buffer[40];

	if (strcmpi(m_parts[m_placedPartCount].m_name, p_name) != 0) {
		for (i = m_placedPartCount + 1; i < m_numberOfParts; i++) {
			if (stricmp(m_parts[i].m_name, p_name) == 0) {
				break;
			}
		}

		strcpy(buffer, m_parts[m_placedPartCount].m_name);
		strcpy(m_parts[m_placedPartCount].m_name, m_parts[i].m_name);
		strcpy(m_parts[i].m_name, buffer);
		Swap(m_parts[m_placedPartCount].m_objectId, m_parts[i].m_objectId);
	}
	FUN_10079050(m_placedPartCount);
	m_placedPartCount++;

	((LegoCarBuild*) m_currentWorld)->SetPlacedPartCount(m_placedPartCount);

	if (m_placedPartCount < m_numberOfParts) {
		FUN_10079680(m_parts[m_placedPartCount].m_wiredName);
	}
}

// FUNCTION: LEGO1 0x10079920
// FUNCTION: BETA10 0x1007225d
void LegoCarBuildAnimPresenter::RotateAroundYAxis(MxFloat p_angle)
{
	if (m_platformAnimNodeData) {
		LegoRotationKey* rotationKey = m_platformAnimNodeData->GetRotationKey(0);

		Mx4DPointFloat
			currentRotation(rotationKey->GetX(), rotationKey->GetY(), rotationKey->GetZ(), rotationKey->GetAngle());
		Mx4DPointFloat additionalRotation(0.0f, 1.0f, 0.0f, -p_angle);
		Mx4DPointFloat newRotation;

		additionalRotation.NormalizeQuaternion();
		newRotation.EqualsHamiltonProduct(currentRotation, additionalRotation);

		if (newRotation[3] < 0.9999) {
			rotationKey->FUN_100739a0(TRUE);
		}
		else {
			rotationKey->FUN_100739a0(FALSE);
		}

		m_platformAnimNodeData->GetRotationKey(0)->SetX(newRotation[0]);
		m_platformAnimNodeData->GetRotationKey(0)->SetY(newRotation[1]);
		m_platformAnimNodeData->GetRotationKey(0)->SetZ(newRotation[2]);
		m_platformAnimNodeData->GetRotationKey(0)->SetAngle(newRotation[3]);

		if (m_carBuildEntity->GetROI()) {
			FUN_1006b9a0(&m_platformAnim, m_shelfFrameBuffer, NULL);
		}
	}
}

// FUNCTION: LEGO1 0x10079a90
// FUNCTION: BETA10 0x10072412
void LegoCarBuildAnimPresenter::MoveShelfForward()
{
	if (m_shelfFrameBuffer >= m_shelfFrameMax) {
		m_shelfFrame = 0.0;
		m_shelfFrameBuffer = m_shelfFrame;
		m_shelfState = e_stopped;
	}
	else if (m_shelfFrameBuffer >= m_shelfFrameInterval + m_shelfFrame) {
		m_shelfFrame = m_shelfFrameInterval + m_shelfFrame;
		m_shelfFrameBuffer = m_shelfFrame;
		m_shelfState = e_stopped;
	}
	else {
		m_shelfFrameBuffer = m_shelfFrameInterval / 10.0f + m_shelfFrameBuffer;
	}
}

// FUNCTION: LEGO1 0x10079b20
// FUNCTION: BETA10 0x100724fa
MxBool LegoCarBuildAnimPresenter::StringEqualsPlatform(const LegoChar* p_string)
{
	return stricmp(p_string, "PLATFORM") == 0;
}

// FUNCTION: LEGO1 0x10079b40
// FUNCTION: BETA10 0x10072534
MxBool LegoCarBuildAnimPresenter::StringEndsOnW(LegoChar* p_param)
{
	return (p_param[strlen(p_param) - 2] == 'W') || (p_param[strlen(p_param) - 2] == 'w');
}

// FUNCTION: LEGO1 0x10079b80
// FUNCTION: BETA10 0x1007258f
MxBool LegoCarBuildAnimPresenter::StringEndsOnYOrN(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'N') || (p_string[strlen(p_string) - 2] == 'n') ||
		   (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// FUNCTION: LEGO1 0x10079bf0
// FUNCTION: BETA10 0x10072624
MxBool LegoCarBuildAnimPresenter::StringEqualsShelf(const LegoChar* p_string)
{
	return strnicmp(p_string, "SHELF", strlen("SHELF")) == 0;
}

// FUNCTION: LEGO1 0x10079c30
// FUNCTION: BETA10 0x100726a6
MxBool LegoCarBuildAnimPresenter::FUN_10079c30(const LegoChar* p_name)
{
	if (PartIsPlaced(p_name)) {
		return FALSE;
	}

	return m_placedPartCount < m_numberOfParts &&
		   strnicmp(p_name, m_parts[m_placedPartCount].m_name, strlen(p_name) - 3) == 0;
}

// FUNCTION: LEGO1 0x10079ca0
// FUNCTION: BETA10 0x10072740
MxBool LegoCarBuildAnimPresenter::PartIsPlaced(const LegoChar* p_name)
{
	for (MxS16 i = 0; i < m_placedPartCount; i++) {
		if (strcmpi(p_name, m_parts[i].m_name) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10079cf0
// FUNCTION: BETA10 0x100727b3
MxBool LegoCarBuildAnimPresenter::StringEndsOnY(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// FUNCTION: LEGO1 0x10079d30
// FUNCTION: BETA10 0x1007280e
MxBool LegoCarBuildAnimPresenter::StringDoesNotEndOnZero(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 1] != '0');
}

// FUNCTION: LEGO1 0x10079d60
// FUNCTION: BETA10 0x1007284c
const LegoChar* LegoCarBuildAnimPresenter::GetWiredNameByPartName(const LegoChar* p_name)
{
	for (MxS16 i = 0; i < m_numberOfParts; i++) {
		if (strcmpi(p_name, m_parts[i].m_name) == 0) {
			return m_parts[i].m_wiredName;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10079dc0
// FUNCTION: BETA10 0x100728d1
void LegoCarBuildAnimPresenter::SetPartObjectIdByName(const LegoChar* p_name, MxS16 p_objectId)
{
	for (MxS16 i = 0; i < m_numberOfParts; i++) {
		if (strcmpi(p_name, m_parts[i].m_name) == 0) {
			m_parts[i].m_objectId = p_objectId;
			return;
		}
	}
}

// FUNCTION: LEGO1 0x10079e20
// FUNCTION: BETA10 0x10072959
const BoundingSphere& LegoCarBuildAnimPresenter::FUN_10079e20()
{
	LegoROI* roi = m_carBuildEntity->GetROI();
	return roi->FindChildROI(m_parts[m_placedPartCount].m_wiredName, roi)->GetWorldBoundingSphere();
}
