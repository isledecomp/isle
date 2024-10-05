#include "legocarbuildpresenter.h"

#include "3dmanager/lego3dmanager.h"
#include "legoentity.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxautolock.h"
#include "realtime/realtime.h"

DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter::UnknownListEntry, 0x0c)
DECOMP_SIZE_ASSERT(LegoCarBuildAnimPresenter, 0x150)

// FUNCTION: LEGO1 0x10078400
// FUNCTION: BETA10 0x100707c0
LegoCarBuildAnimPresenter::LegoCarBuildAnimPresenter()
{
	m_unk0xbc = 0;
	m_unk0xbe = 0;
	m_unk0xc0 = 0;
	m_unk0x128 = NULL;
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
	if (m_unk0x128) {
		for (MxS16 i = 0; i < m_unk0xbe; i++) {
			delete m_unk0x128[i].m_unk0x00;
			delete m_unk0x128[i].m_unk0x04;
		}
		delete[] m_unk0x128;
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

// STUB: LEGO1 0x100788c0
// STUB: BETA10 0x10070b56
void LegoCarBuildAnimPresenter::ReadyTickle()
{
	// TODO
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
		m_unk0xc0 = 10;
	}

	MxS16 i;

	for (i = 0; i < m_unk0xbe; i++) {
		if (m_unk0xc0 == i) {
			FUN_10079680(m_unk0x128[i].m_unk0x04);
		}
		else {
			FUN_100795d0(m_unk0x128[i].m_unk0x04);
		}

		if (i < m_unk0xc0) {
			FUN_10079050(i);
			FUN_10079680(m_unk0x128[i].m_unk0x00);
		}

		LegoChar* name = m_unk0x128[i].m_unk0x04;

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
	FUN_10079090(m_unk0x128[p_index].m_unk0x04, m_unk0x128[p_index].m_unk0x00);
	FUN_100795d0(m_unk0x128[p_index].m_unk0x04);
}

// STUB: LEGO1 0x10079090
// STUB: BETA10 0x10071584
void LegoCarBuildAnimPresenter::FUN_10079090(LegoChar* p_param1, LegoChar* p_param2)
{
	// TODO
}

// STUB: LEGO1 0x10079160
// STUB: BETA10 0x1007165d
void LegoCarBuildAnimPresenter::FUN_10079160()
{
	// called from LegoCarBuildAnimPresenter::StreamingTickle()
	// TODO
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

// FUNCTION: LEGO1 0x10079b80
// FUNCTION: BETA10 0x1007258f
MxBool LegoCarBuildAnimPresenter::StringEndsOnYOrN(const LegoChar* p_string)
{
	return (p_string[strlen(p_string) - 2] == 'N') || (p_string[strlen(p_string) - 2] == 'n') ||
		   (p_string[strlen(p_string) - 2] == 'Y') || (p_string[strlen(p_string) - 2] == 'y');
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
	for (MxS16 i = 0; i < m_unk0xc0; i++) {
		if (strcmpi(p_name, m_unk0x128[i].m_unk0x00) == 0) {
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
	return roi->FindChildROI(m_unk0x128[m_unk0xc0].m_unk0x04, roi)->GetWorldBoundingSphere();
}
