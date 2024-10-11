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
#include "mxautolock.h"
#include "mxcompositepresenter.h"
#include "realtime/realtime.h"

DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter::UnknownListEntry, 0x0c)
DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter, 0x150)

// FUNCTION: LEGO1 0x10078400
// FUNCTION: BETA10 0x100707c0
LegoCarBuildAnimPresenter::LegoCarBuildAnimPresenter()
{
	m_unk0xbc = 0;
	m_numberOfParts = 0;
	m_placedPartCount = 0;
	m_parts = NULL;
	m_unk0xc4 = NULL;
	m_unk0x130 = 0;
	m_unk0x12c = 0;
	m_unk0x134 = 0;
	m_unk0x138 = 0;
	m_unk0x13c = 0;
	m_unk0x140 = NULL;
	m_unk0x144 = -1;
	m_unk0x148 = -1;
	m_mainSourceId = NULL;
}

// FUNCTION: LEGO1 0x10078500
void LegoCarBuildAnimPresenter::RepeatingTickle()
{
	// empty
}

// FUNCTION: LEGO1 0x10078680
// FUNCTION: BETA10 0x1007091e
LegoCarBuildAnimPresenter::~LegoCarBuildAnimPresenter()
{
	if (m_parts) {
		for (MxS16 i = 0; i < m_numberOfParts; i++) {
			delete m_parts[i].m_name;
			delete m_parts[i].m_wiredName;
		}
		delete[] m_parts;
	}

	m_unk0xc8.GetRoot()->SetNumChildren(0);
	*m_unk0xc8.GetRoot()->GetChildren() = NULL;

	if (m_mainSourceId) {
		delete[] m_mainSourceId;
	}
}

// STUB: LEGO1 0x10078790
void LegoCarBuildAnimPresenter::PutFrame()
{
	// TODO
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

#ifdef NDEBUG
		if (!m_anim) {
			return;
		}
#else
		assert(m_anim);
#endif
	}

	m_unk0x140 = (LegoEntity*) m_currentWorld->Find("MxEntity", "Dunebld");

	if (!m_unk0x140) {
		m_unk0x140 = (LegoEntity*) m_currentWorld->Find("MxEntity", "Chptrbld");
	}

	if (!m_unk0x140) {
		m_unk0x140 = (LegoEntity*) m_currentWorld->Find("MxEntity", "Jetbld");
	}

	if (!m_unk0x140) {
		m_unk0x140 = (LegoEntity*) m_currentWorld->Find("MxEntity", "bldrace");
	}

	if (m_unk0x140) {
		((LegoCarBuild*) m_currentWorld)->SetUnknown0x258(this);
		m_placedPartCount = ((LegoCarBuild*) m_currentWorld)->GetPlacedPartCount();
		SetUnknown0xbc(1);
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
	if (!m_unk0x140->GetROI()) {
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
					roi->FUN_100a9dd0();
					roi->FUN_100a9350("lego red");
				}
			}
		}
	}

	LegoVideoManager* videoManager = VideoManager();
	assert(videoManager); // verifies variable name 'videoManager'

	Lego3DView* lego3dview = videoManager->Get3DManager()->GetLego3DView();
	LegoROI* videoManagerROI = videoManager->GetViewROI();
	LegoROI* local60 = m_unk0x140->GetROI();
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

	Vector3 cameraPosition(camera->GetWorldPosition());
	Vector3 upVec(camera->GetWorldUp());
	Vector3 targetPosition(targetROI->GetWorldPosition());

	MxMatrix localTransform;

	dirVec[0] = targetPosition[0] - cameraPosition[0];
	dirVec[1] = targetPosition[1] - cameraPosition[1];
	dirVec[2] = targetPosition[2] - cameraPosition[2];
	dirVec.Unitize();

	CalcLocalTransform(cameraPosition, dirVec, upVec, localTransform);

	videoManagerROI->WrappedSetLocalTransform(localTransform);
	lego3dview->Moved(*videoManagerROI);
	videoManager->Get3DManager()->SetFrustrum(fov, 0.1, 250.0);

	m_unk0xe0 = local60->FindChildROI("VIEW", local60)->GetLocal2World();

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
		m_unk0xbc = 0;
	}
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
			m_unk0xc4 = data;
			if (m_unk0xc4->GetNumRotationKeys() == 0) {
				LegoRotationKey* key = new LegoRotationKey();
				m_unk0xc4->SetNumRotationKeys(1);
				m_unk0xc4->SetRotationKeys(key);
			}
		}
		else {
			if (StringEndsOnYOrN(name)) {
				m_numberOfParts++;
			}
			else {
				if (m_unk0x134 == 0.0f && StringEqualsShelf(name)) {
					m_unk0x134 = m_anim->GetDuration();
					m_unk0x138 = m_unk0x134 / (data->GetNumTranslationKeys() - 1);
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
	destData->FUN_100a0360(data2->GetName());

	destNode->SetNumChildren(1);
	children = new LegoTreeNode*;
	assert(children);
	*children = FindNodeByName(m_anim->GetRoot(), "PLATFORM");

	destNode->SetChildren(children);
	m_unk0xc8.SetRoot(destNode);
}

// STUB: LEGO1 0x100795d0
// STUB: BETA10 0x10071d96
void LegoCarBuildAnimPresenter::FUN_100795d0(LegoChar* p_param)
{
	// TODO
}

// STUB: LEGO1 0x10079680
// STUB: BETA10 0x10071ec5
void LegoCarBuildAnimPresenter::FUN_10079680(LegoChar* p_param)
{
	// TODO
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

// FUNCTION: LEGO1 0x10079920
// FUNCTION: BETA10 0x1007225d
void LegoCarBuildAnimPresenter::RotateAroundYAxis(MxFloat p_angle)
{
	if (m_unk0xc4) {
		LegoRotationKey* rotationKey = m_unk0xc4->GetRotationKey(0);

		Mx4DPointFloat
			currentRotation(rotationKey->GetX(), rotationKey->GetY(), rotationKey->GetZ(), rotationKey->GetAngle());
		Mx4DPointFloat additionalRotation(0.0f, 1.0f, 0.0f, -p_angle);
		Mx4DPointFloat newRotation;

		additionalRotation.NormalizeQuaternion();
		newRotation.EqualsHamiltonProduct(&currentRotation, &additionalRotation);

		if (newRotation[3] < 0.9999) {
			rotationKey->FUN_100739a0(TRUE);
		}
		else {
			rotationKey->FUN_100739a0(FALSE);
		}

		m_unk0xc4->GetRotationKey(0)->SetX(newRotation[0]);
		m_unk0xc4->GetRotationKey(0)->SetY(newRotation[1]);
		m_unk0xc4->GetRotationKey(0)->SetZ(newRotation[2]);
		m_unk0xc4->GetRotationKey(0)->SetAngle(newRotation[3]);

		if (m_unk0x140->GetROI()) {
			FUN_1006b9a0(&m_unk0xc8, m_unk0x12c, NULL);
		}
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

// STUB: LEGO1 0x10079c30
// STUB: BETA10 0x100726a6
MxBool LegoCarBuildAnimPresenter::FUN_10079c30(const LegoChar* p_name)
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10079ca0
// FUNCTION: BETA10 0x10072740
MxBool LegoCarBuildAnimPresenter::FUN_10079ca0(const LegoChar* p_name)
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
MxBool LegoCarBuildAnimPresenter::FUN_10079cf0(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
}

// FUNCTION: LEGO1 0x10079e20
// FUNCTION: BETA10 0x10072959
const BoundingSphere& LegoCarBuildAnimPresenter::FUN_10079e20()
{
	LegoROI* roi = m_unk0x140->GetROI();
	return roi->FindChildROI(m_parts[m_placedPartCount].m_wiredName, roi)->GetWorldBoundingSphere();
}
