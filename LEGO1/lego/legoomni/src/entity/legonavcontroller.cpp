#include "legonavcontroller.h"

#include "3dmanager/lego3dmanager.h"
#include "act3.h"
#include "infocenter.h"
#include "legoanimationmanager.h"
#include "legocameracontroller.h"
#include "legocharactermanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legolocations.h"
#include "legomain.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxutilities.h"
#include "realtime/realtime.h"
#include "realtime/realtimeview.h"
#include "viewmanager/viewmanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoNavController, 0x70)

//////////////////////////////////////////////////////////////////////

#ifndef M_PI
#define M_PI 3.1416
#endif
#ifdef DTOR
#undef DTOR
#endif
#define DTOR(angle) ((angle) * M_PI / 180.)

//////////////////////////////////////////////////////////////////////

// GLOBAL: LEGO1 0x100f4c28
int LegoNavController::g_defdeadZone = 40;

// GLOBAL: LEGO1 0x100f4c2c
float LegoNavController::g_defzeroThreshold = 0.001f;

// GLOBAL: LEGO1 0x100f4c30
float LegoNavController::g_defmaxLinearVel = 40.0f;

// GLOBAL: LEGO1 0x100f4c34
float LegoNavController::g_defmaxRotationalVel = 20.0f;

// GLOBAL: LEGO1 0x100f4c38
float LegoNavController::g_defmaxLinearAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c3c
float LegoNavController::g_defmaxRotationalAccel = 30.0f;

// GLOBAL: LEGO1 0x100f4c40
float LegoNavController::g_defminLinearAccel = 4.0f;

// GLOBAL: LEGO1 0x100f4c44
float LegoNavController::g_defminRotationalAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c48
float LegoNavController::g_defmaxLinearDeccel = 50.0f;

// GLOBAL: LEGO1 0x100f4c4c
float LegoNavController::g_defmaxRotationalDeccel = 50.0f;

// GLOBAL: LEGO1 0x100f4c50
float LegoNavController::g_defrotSensitivity = 0.4f;

// GLOBAL: LEGO1 0x100f4c54
MxBool LegoNavController::g_defuseRotationalVel = FALSE;

// GLOBAL: LEGO1 0x100f66a0
MxU32 g_changeLight = FALSE;

// GLOBAL: LEGO1 0x100f66a4
MxS32 g_locationCalcStep = 0;

// GLOBAL: LEGO1 0x100f66a8
MxS32 g_nextLocation = 0;

// GLOBAL: LEGO1 0x100f66ac
MxBool g_resetPlants = FALSE;

// GLOBAL: LEGO1 0x100f66b0
MxS32 g_animationCalcStep = 0;

// GLOBAL: LEGO1 0x100f66b4
MxS32 g_nextAnimation = 0;

// GLOBAL: LEGO1 0x100f66b8
MxU32 g_switchAct = FALSE;

// GLOBAL: LEGO1 0x100f66bc
LegoAnimationManager::PlayMode g_unk0x100f66bc = LegoAnimationManager::e_unk2;

// GLOBAL: LEGO1 0x100f66c0
char g_debugPassword[] = "OGEL";

// GLOBAL: LEGO1 0x100f66c8
char* g_currentInput = g_debugPassword;

// GLOBAL: LEGO1 0x100f66cc
MxS32 g_unk0x100f66cc = -1;

// GLOBAL: LEGO1 0x100f66d0
MxBool g_enableMusic = TRUE;

// GLOBAL: LEGO1 0x100f66d4
MxU32 g_fpsEnabled = TRUE;

// FUNCTION: LEGO1 0x10054ac0
LegoNavController::LegoNavController()
{
	SetToDefaultParams();

	m_linearVel = 0.0f;
	m_rotationalVel = 0.0f;
	m_targetLinearVel = 0.0f;
	m_targetRotationalVel = 0.0f;
	m_linearAccel = 0.0f;
	m_rotationalAccel = 0.0f;
	m_trackDefault = FALSE;
	m_unk0x5d = FALSE;
	m_unk0x6c = FALSE;
	m_unk0x64 = 0.0f;
	m_unk0x68 = 0.0f;
	m_unk0x60 = 0.0f;

	m_lastTime = Timer()->GetTime();

	InputManager()->Register(this);
}

// FUNCTION: LEGO1 0x10054c30
LegoNavController::~LegoNavController()
{
	InputManager()->UnRegister(this);
}

// FUNCTION: LEGO1 0x10054ca0
void LegoNavController::SetControlMax(int p_hMax, int p_vMax)
{
	m_hMax = p_hMax;
	m_vMax = p_vMax;

	if (VideoManager()->GetVideoParam().Flags().GetFullScreen()) {
		m_hMax = 640;
		m_vMax = 480;
	}
}

// FUNCTION: LEGO1 0x10054cd0
// FUNCTION: BETA10 0x1009ad76
void LegoNavController::SetToDefaultParams()
{
	m_deadZone = g_defdeadZone;
	m_zeroThreshold = g_defzeroThreshold;
	m_maxRotationalAccel = g_defmaxRotationalAccel;
	m_maxLinearAccel = g_defmaxLinearAccel;
	m_minRotationalAccel = g_defminRotationalAccel;
	m_minLinearAccel = g_defminLinearAccel;
	m_maxRotationalDeccel = g_defmaxRotationalDeccel;
	m_maxLinearDeccel = g_defmaxLinearDeccel;
	m_maxRotationalVel = g_defmaxRotationalVel;
	m_maxLinearVel = g_defmaxLinearVel;
	m_useRotationalVel = g_defuseRotationalVel;
	m_rotSensitivity = g_defrotSensitivity;
}

// FUNCTION: LEGO1 0x10054d40
void LegoNavController::GetDefaults(
	int* p_dz,
	float* p_lv,
	float* p_rv,
	float* p_la,
	float* p_ra,
	float* p_ld,
	float* p_rd,
	float* p_lmina,
	float* p_rmina,
	float* p_rs,
	MxBool* p_urs
)
{
	*p_dz = g_defdeadZone;
	*p_lv = g_defmaxLinearVel;
	*p_rv = g_defmaxRotationalVel;
	*p_la = g_defmaxLinearAccel;
	*p_ra = g_defmaxRotationalAccel;
	*p_ld = g_defmaxLinearDeccel;
	*p_rd = g_defmaxRotationalDeccel;
	*p_lmina = g_defminLinearAccel;
	*p_rmina = g_defminRotationalAccel;
	*p_rs = g_defrotSensitivity;
	*p_urs = g_defuseRotationalVel;
}

// FUNCTION: LEGO1 0x10054dd0
void LegoNavController::SetDefaults(
	int p_dz,
	float p_lv,
	float p_rv,
	float p_la,
	float p_ra,
	float p_ld,
	float p_rd,
	float p_lmina,
	float p_rmina,
	float p_rs,
	MxBool p_urs
)
{
	g_defdeadZone = p_dz;
	g_defmaxLinearVel = p_lv;
	g_defmaxRotationalVel = p_rv;
	g_defmaxLinearAccel = p_la;
	g_defmaxRotationalAccel = p_ra;
	g_defmaxLinearDeccel = p_ld;
	g_defmaxRotationalDeccel = p_rd;
	g_defminLinearAccel = p_lmina;
	g_defminRotationalAccel = p_rmina;
	g_defrotSensitivity = p_rs;
	g_defuseRotationalVel = p_urs;
}

// FUNCTION: LEGO1 0x10054e40
void LegoNavController::SetTargets(int p_hPos, int p_vPos, MxBool p_accel)
{
	if (m_trackDefault != FALSE) {
		SetToDefaultParams();
	}

	if (p_accel != FALSE) {
		m_targetRotationalVel = CalculateNewTargetVel(p_hPos, m_hMax / 2, m_maxRotationalVel);
		m_targetLinearVel = CalculateNewTargetVel(m_vMax - p_vPos, m_vMax / 2, m_maxLinearVel);
		m_rotationalAccel = CalculateNewAccel(p_hPos, m_hMax / 2, m_maxRotationalAccel, (int) m_minRotationalAccel);
		m_linearAccel = CalculateNewAccel(m_vMax - p_vPos, m_vMax / 2, m_maxLinearAccel, (int) m_minLinearAccel);
	}
	else {
		m_targetRotationalVel = 0;
		m_targetLinearVel = 0;
		m_linearAccel = m_maxLinearDeccel;
		m_rotationalAccel = m_maxRotationalDeccel;
	}
}

// FUNCTION: LEGO1 0x10054f10
float LegoNavController::CalculateNewTargetVel(int p_pos, int p_center, float p_max)
{
	float newVel;
	int diff = p_pos - p_center;

	if (diff > m_deadZone) {
		newVel = (diff - m_deadZone) * p_max / (p_center - m_deadZone);
	}
	else if (diff < -m_deadZone) {
		newVel = (diff + m_deadZone) * p_max / (p_center - m_deadZone);
	}
	else {
		newVel = 0.0;
	}

	return newVel;
}

// FUNCTION: LEGO1 0x10054f90
float LegoNavController::CalculateNewAccel(int p_pos, int p_center, float p_max, int p_min)
{
	float newAccel;
	int diff = p_pos - p_center;

	newAccel = Abs(diff) * p_max / p_center;

	if (newAccel < p_min) {
		newAccel = (float) p_min;
	}

	return newAccel;
}

// FUNCTION: LEGO1 0x10054fe0
float LegoNavController::CalculateNewVel(float p_targetVel, float p_currentVel, float p_accel, float p_time)
{
	float newVel = p_currentVel;

	float velDiff = p_targetVel - p_currentVel;
	int vSign = velDiff > 0 ? 1 : -1;

	if (Abs(velDiff) > m_zeroThreshold) {
		float deltaVel = p_accel * p_time;
		newVel = p_currentVel + (deltaVel * vSign);

		if (vSign > 0) {
			newVel = Min(newVel, p_targetVel);
		}
		else {
			newVel = Max(newVel, p_targetVel);
		}
	}

	return newVel;
}

// FUNCTION: LEGO1 0x10055080
MxBool LegoNavController::CalculateNewPosDir(
	const Vector3& p_curPos,
	const Vector3& p_curDir,
	Vector3& p_newPos,
	Vector3& p_newDir,
	const Vector3* p_und
)
{
	if (!g_isWorldActive) {
		return FALSE;
	}

	MxBool changed = FALSE;
	MxBool und = FALSE;

	MxTime currentTime = Timer()->GetTime();
	float deltaTime = (currentTime - m_lastTime) / 1000.0;
	m_lastTime = currentTime;

	if (ProcessKeyboardInput() == FAILURE) {
		ProcessJoystickInput(und);
	}

	if (m_useRotationalVel) {
		m_rotationalVel = CalculateNewVel(m_targetRotationalVel, m_rotationalVel, m_rotationalAccel * 40.0f, deltaTime);
	}
	else {
		m_rotationalVel = m_targetRotationalVel;
	}

	m_linearVel = CalculateNewVel(m_targetLinearVel, m_linearVel, m_linearAccel, deltaTime);

	if (und || (Abs(m_rotationalVel) > m_zeroThreshold) || (Abs(m_linearVel) > m_zeroThreshold)) {
		float rot_mat[3][3];
		Mx3DPointFloat delta_pos, new_dir, new_pos;

		if (m_linearVel < -(m_maxLinearVel * 0.4f)) {
			m_linearVel = -(m_maxLinearVel * 0.4f);
		}

		VXS3(delta_pos, p_curDir, m_linearVel * deltaTime);
		VPV3(p_newPos, p_curPos, delta_pos);

		float delta_rad;
		if (m_useRotationalVel) {
			delta_rad = DTOR(m_rotationalVel * deltaTime);
		}
		else {
			delta_rad = DTOR(m_rotationalVel * m_rotSensitivity);
		}

		if (p_und != NULL && (*p_und)[1] < 0.0f) {
			delta_rad = -delta_rad;
		}

		IDENTMAT3(rot_mat);
		rot_mat[0][0] = rot_mat[2][2] = cos(delta_rad);
		rot_mat[0][2] = rot_mat[2][0] = sin(delta_rad);
		rot_mat[0][2] *= -1.0f;
		VXM3(p_newDir, p_curDir, rot_mat);

		changed = TRUE;
	}

	if (m_unk0x5d) {
		float rot_mat[3][3];
		Mx3DPointFloat delta_pos, new_pos, new_dir;

		if (changed) {
			SET3(new_pos, p_newPos);
			SET3(new_dir, p_newDir);
		}
		else {
			SET3(new_pos, p_curPos);
			SET3(new_dir, p_curDir);
		}

		if (m_unk0x64 != 0.0f) {
			delta_pos[0] = new_dir[0] * m_unk0x64;
			delta_pos[1] = new_dir[1] * m_unk0x64;
			delta_pos[2] = new_dir[2] * m_unk0x64;
		}
		else {
			FILLVEC3(delta_pos, 0.0f);
		}

		delta_pos[1] += m_unk0x60;
		VPV3(p_newPos, new_pos, delta_pos);

		if (m_unk0x68 != 0.0f) {
			float delta_rad = DTOR(m_unk0x68);
			IDENTMAT3(rot_mat);
			rot_mat[0][0] = rot_mat[2][2] = cos(delta_rad);
			rot_mat[0][2] = rot_mat[2][0] = sin(delta_rad);
			rot_mat[0][2] *= -1.0f;
			VXM3(p_newDir, new_dir, rot_mat);
		}
		else {
			SET3(p_newDir, new_dir);
		}

		m_unk0x60 = m_unk0x64 = m_unk0x68 = 0.0f;
		m_unk0x5d = FALSE;
		changed = TRUE;
	}

	return changed;
}

// FUNCTION: LEGO1 0x10055500
// FUNCTION: BETA10 0x1009bff8
MxResult LegoNavController::UpdateLocation(const char* p_location)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < (MxS32) sizeOfArray(g_locations); i++) {
		if (!strcmpi(p_location, g_locations[i].m_name)) {
			MxMatrix mat;
			LegoROI* viewROI = VideoManager()->GetViewROI();

			CalcLocalTransform(g_locations[i].m_position, g_locations[i].m_direction, g_locations[i].m_up, mat);

			Mx3DPointFloat vec;
			vec.Clear();

			viewROI->FUN_100a5a30(vec);
			viewROI->WrappedSetLocalTransform(mat);
			VideoManager()->Get3DManager()->Moved(*viewROI);

			SoundManager()->UpdateListener(
				viewROI->GetWorldPosition(),
				viewROI->GetWorldDirection(),
				viewROI->GetWorldUp(),
				viewROI->GetWorldVelocity()
			);

			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10055620
// FUNCTION: BETA10 0x1009c145
MxResult LegoNavController::UpdateLocation(MxU32 p_location)
{
	MxResult result = FAILURE;

	if (p_location < sizeOfArray(g_locations)) {
		MxMatrix mat;
		LegoROI* viewROI = VideoManager()->GetViewROI();

		CalcLocalTransform(
			g_locations[p_location].m_position,
			g_locations[p_location].m_direction,
			g_locations[p_location].m_up,
			mat
		);

		Mx3DPointFloat vec;
		vec.Clear();

		viewROI->FUN_100a5a30(vec);
		viewROI->WrappedSetLocalTransform(mat);
		VideoManager()->Get3DManager()->Moved(*viewROI);

		SoundManager()->UpdateListener(
			viewROI->GetWorldPosition(),
			viewROI->GetWorldDirection(),
			viewROI->GetWorldUp(),
			viewROI->GetWorldVelocity()
		);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10055720
// FUNCTION: BETA10 0x1009c259
LegoLocation* LegoNavController::GetLocation(MxU32 p_location)
{
	if (p_location < sizeOfArray(g_locations)) {
		return &g_locations[p_location];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10055740
MxS32 LegoNavController::GetNumLocations()
{
	return sizeOfArray(g_locations);
}

// FUNCTION: LEGO1 0x10055750
MxResult LegoNavController::ProcessJoystickInput(MxBool& p_und)
{
	LegoOmni* instance = LegoOmni::GetInstance();

	if (instance->GetInputManager()) {
		MxS32 joystickX;
		MxS32 joystickY;
		DWORD buttonState;
		MxS32 povPosition;

		if (instance->GetInputManager()
				->GetJoystickState((MxU32*) &joystickX, (MxU32*) &joystickY, &buttonState, (MxU32*) &povPosition) !=
			FAILURE) {
			MxU32 yVal = (joystickY * m_vMax) / 100;
			MxU32 xVal = (joystickX * m_hMax) / 100;

			if (joystickX <= 45 || joystickX >= 55 || joystickY <= 45 || joystickY >= 55) {
				m_targetLinearVel = CalculateNewTargetVel(m_vMax - yVal, m_vMax / 2, m_maxLinearVel);
				m_linearAccel = CalculateNewAccel(m_vMax - yVal, m_vMax / 2, m_maxLinearAccel, (int) m_minLinearAccel);
				m_targetRotationalVel = CalculateNewTargetVel(xVal, m_hMax / 2, m_maxRotationalVel);
				m_rotationalAccel =
					CalculateNewAccel(xVal, m_hMax / 2, m_maxRotationalAccel, (int) m_minRotationalAccel);
			}
			else {
				m_targetRotationalVel = 0.0;
				m_targetLinearVel = 0.0;
				m_linearAccel = m_maxLinearDeccel;
				m_rotationalAccel = m_maxRotationalDeccel;
			}

			if (povPosition >= 0) {
				LegoWorld* world = CurrentWorld();

				if (world && world->GetCamera()) {
					world->GetCamera()->FUN_10012320(DTOR(povPosition));
					p_und = TRUE;
				}
			}

			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100558b0
MxResult LegoNavController::ProcessKeyboardInput()
{
	MxBool bool1 = FALSE;
	MxBool bool2 = FALSE;
	LegoInputManager* inputManager = LegoOmni::GetInstance()->GetInputManager();
	MxU32 keyFlags;

	if (inputManager == NULL || inputManager->GetNavigationKeyStates(keyFlags) == FAILURE) {
		return FAILURE;
	}

	if (keyFlags == 0) {
		if (m_unk0x6c) {
			m_targetRotationalVel = 0.0;
			m_targetLinearVel = 0.0;
			m_rotationalAccel = m_maxRotationalDeccel;
			m_linearAccel = m_maxLinearDeccel;
			m_unk0x6c = FALSE;
		}

		return FAILURE;
	}

	m_unk0x6c = TRUE;

	MxS32 hMax;
	if ((keyFlags & LegoInputManager::c_leftOrRight) == LegoInputManager::c_left) {
		hMax = 0;
	}
	else if ((keyFlags & LegoInputManager::c_leftOrRight) == LegoInputManager::c_right) {
		hMax = m_hMax;
	}
	else {
		m_targetRotationalVel = 0.0;
		m_rotationalAccel = m_maxRotationalDeccel;
		bool1 = TRUE;
	}

	MxS32 vMax;
	if ((keyFlags & LegoInputManager::c_upOrDown) == LegoInputManager::c_up) {
		vMax = 0;
	}
	else if ((keyFlags & LegoInputManager::c_upOrDown) == LegoInputManager::c_down) {
		vMax = m_vMax;
	}
	else {
		m_targetLinearVel = 0.0;
		m_linearAccel = m_maxLinearDeccel;
		bool2 = TRUE;
	}

	MxFloat val = keyFlags & LegoInputManager::c_bit5 ? 1.0f : 4.0f;
	MxFloat val2 = keyFlags & LegoInputManager::c_bit5 ? 1.0f : 2.0f;

	if (!bool1) {
		m_targetRotationalVel = CalculateNewTargetVel(hMax, m_hMax / 2, m_maxRotationalVel);
		m_rotationalAccel =
			CalculateNewAccel(hMax, m_hMax / 2, m_maxRotationalAccel / val, (int) (m_minRotationalAccel / val2));
	}

	if (!bool2) {
		m_targetLinearVel = CalculateNewTargetVel(m_vMax - vMax, m_vMax / 2, m_maxLinearVel);
		m_linearAccel =
			CalculateNewAccel(m_vMax - vMax, m_vMax / 2, m_maxLinearAccel / val, (int) (m_minLinearAccel / val2));
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10055a60
// FUNCTION: BETA10 0x1009c712
MxLong LegoNavController::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == c_notificationKeyPress) {
		m_unk0x5d = TRUE;
		MxU8 key = ((LegoEventNotificationParam&) p_param).GetKey();

		switch (key) {
		case VK_PAUSE: // Pause game
			if (Lego()->IsPaused()) {
				Lego()->Resume();
			}
			else {
				Lego()->Pause();
			}
			break;
		case VK_ESCAPE: { // Return to infocenter
			LegoWorld* currentWorld = CurrentWorld();
			if (currentWorld != NULL) {
				InfocenterState* state = (InfocenterState*) GameState()->GetState("InfocenterState");
				assert(state);

				if (state != NULL && state->m_unk0x74 != 8 && currentWorld->Escape()) {
					BackgroundAudioManager()->Stop();
					TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
					state->m_unk0x74 = 8;
				}
			}
			break;
		}
		case VK_SPACE: // Interrupt/end animations or free navigation
			AnimationManager()->FUN_10061010(TRUE);
			break;
		case 'Z': { // Make nearby plants "dance"
			LegoOmni* omni = Lego();

			if (omni->GetCurrentWorld() != NULL && omni->GetCurrentWorld()->GetWorldId() == LegoOmni::e_act1) {
				LegoVideoManager* videoMgr = LegoOmni::GetInstance()->GetVideoManager();
				ViewROI* roi = videoMgr->GetViewROI();
				ViewManager* view = videoMgr->Get3DManager()->GetLego3DView()->GetViewManager();
				LegoPlantManager* plantMgr = LegoOmni::GetInstance()->GetPlantManager();
				Mx3DPointFloat viewPosition(roi->GetWorldPosition());
				MxS32 numPlants = plantMgr->GetNumPlants();

				for (MxS32 i = 0; i < numPlants; i++) {
					LegoEntity* entity = plantMgr->CreatePlant(i, NULL, LegoOmni::e_act1);

					if (entity != NULL && !entity->GetUnknown0x10IsSet(LegoEntity::c_altBit1)) {
						LegoROI* roi = entity->GetROI();

						if (roi != NULL && roi->GetVisibility()) {
							const BoundingBox& box = roi->GetWorldBoundingBox();

							if (view->IsBoundingBoxInFrustum(box)) {
								Mx3DPointFloat roiPosition(roi->GetWorldPosition());
								roiPosition -= viewPosition;

								if (roiPosition.LenSquared() < 2000.0 || roi->GetUnknown0xe0() > 0) {
									entity->ClickAnimation();
								}
							}
						}
					}
				}
			}
			break;
		}
		case 'k':
		case 'm': { // Keys need to be uppercased to trigger this code, but seems dysfunctional
			if (g_unk0x100f66cc == -1) {
				g_unk0x100f66cc = 0;
			}
			else {
				CharacterManager()->ReleaseActor(CharacterManager()->GetActorName(g_unk0x100f66cc));

				if (key == 'k') {
					g_unk0x100f66cc++;
					if (g_unk0x100f66cc >= CharacterManager()->GetNumActors()) {
						g_unk0x100f66cc = 0;
					}
				}
				else {
					g_unk0x100f66cc--;
					if (g_unk0x100f66cc < 0) {
						g_unk0x100f66cc = CharacterManager()->GetNumActors() - 1;
					}
				}
			}

			LegoROI* roi = CharacterManager()->GetActorROI(CharacterManager()->GetActorName(g_unk0x100f66cc), TRUE);
			if (roi != NULL) {
				MxMatrix mat;
				ViewROI* viewRoi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
				const float* position = viewRoi->GetWorldPosition();
				const float* direction = viewRoi->GetWorldDirection();
				const float* up = viewRoi->GetWorldUp();
				CalcLocalTransform(position, direction, up, mat);
				mat.TranslateBy(direction[0] * 2.0f, direction[1] - 1.0, direction[2] * 2.0f);
				roi->UpdateTransformationRelativeToParent(mat);
			}
			break;
		}
		case '{': { // Saves the game. Can't actually be triggered
			InfocenterState* state = (InfocenterState*) GameState()->GetState("InfocenterState");
			if (state && state->HasRegistered()) {
				GameState()->Save(0);
			}
			break;
		}
		default:
			// Check if the the key is part of the debug password
			if (!*g_currentInput) {
				// password "protected" debug shortcuts
				switch (((LegoEventNotificationParam&) p_param).GetKey()) {
				case VK_TAB:
					VideoManager()->ToggleFPS(g_fpsEnabled);
					if (g_fpsEnabled) {
						g_fpsEnabled = FALSE;
					}
					else {
						g_fpsEnabled = TRUE;
					}
				default:
					m_unk0x5d = FALSE;
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					if (g_changeLight && key <= '1') {
						LegoROI* roi = VideoManager()->GetViewROI();
						Tgl::FloatMatrix4 matrix;
						Matrix4 in(matrix);
						roi->GetLocalTransform(in);
						VideoManager()->Get3DManager()->GetLego3DView()->SetLightTransform(key - '0', matrix);
						g_changeLight = FALSE;
					}
					else if (g_locationCalcStep) {
						if (g_locationCalcStep == 1) {
							// Calculate base offset into g_locations
							g_nextLocation = (key - '0') * 10;
							g_locationCalcStep = 2;
						}
						else {
							// Add to base g_locations offset
							g_nextLocation += key - '0';
							g_locationCalcStep = 0;
							UpdateLocation(g_nextLocation);
						}
					}
					else if (g_animationCalcStep) {
						if (g_animationCalcStep == 1) {
							// Calculate base offset into possible animation object IDs (up to 999)
							g_nextAnimation = (key - '0') * 100;
							g_animationCalcStep = 2;
						}
						else if (g_animationCalcStep == 2) {
							// Add to animation object ID offset
							g_nextAnimation += (key - '0') * 10;
							g_animationCalcStep = 3;
						}
						else {
							// Add to animation object ID offset
							g_nextAnimation += key - '0';
							g_animationCalcStep = 0;
							AnimationManager()->FUN_10060dc0(
								g_nextAnimation,
								NULL,
								TRUE,
								g_unk0x100f66bc,
								NULL,
								TRUE,
								TRUE,
								TRUE,
								TRUE
							);

							g_unk0x100f66bc = LegoAnimationManager::e_unk2;
						}
					}

					if (g_switchAct && key >= '1' && key <= '5') {
						switch (GameState()->GetCurrentAct()) {
						case LegoGameState::e_act1:
							GameState()->m_currentArea = LegoGameState::e_isle;
							break;
						case LegoGameState::e_act2:
							GameState()->m_currentArea = LegoGameState::e_act2main;
							break;
						case LegoGameState::e_act3:
							GameState()->m_currentArea = LegoGameState::e_act3script;
							break;
						}

						switch (key) {
						case '1':
							GameState()->SetCurrentAct(LegoGameState::e_act1);
							GameState()->SwitchArea(LegoGameState::e_isle);
							break;
						case '2':
							GameState()->SwitchArea(LegoGameState::e_act2main);
							break;
						case '3':
							GameState()->SwitchArea(LegoGameState::e_act3script);
							break;
						case '4': {
							Act3State* act3State = (Act3State*) GameState()->GetState("Act3State");
							if (act3State == NULL) {
								act3State = new Act3State();
								assert(act3State);
								GameState()->RegisterState(act3State);
							}

							GameState()->SetCurrentAct(LegoGameState::e_act3);
							act3State->m_unk0x08 = 2;
							GameState()->m_currentArea = LegoGameState::e_act3script;
							GameState()->SwitchArea(LegoGameState::e_infomain);
							break;
						}
						case '5': {
							Act3State* act3State = (Act3State*) GameState()->GetState("Act3State");
							if (act3State == NULL) {
								act3State = new Act3State();
								assert(act3State);
								GameState()->RegisterState(act3State);
							}

							GameState()->SetCurrentAct(LegoGameState::e_act3);
							act3State->m_unk0x08 = 3;
							GameState()->m_currentArea = LegoGameState::e_act3script;
							GameState()->SwitchArea(LegoGameState::e_infomain);
							break;
						}
						}

						g_switchAct = FALSE;
					}
					else {
						MxDSAction action;
						action.SetObjectId(key - '0');
						action.SetAtomId(MxAtomId("q:\\lego\\media\\model\\common\\common", e_lowerCase2));
						LegoOmni::GetInstance()->Start(&action);
					}
					break;
				case 'A':
					if (g_animationCalcStep == 1) {
						Lego()->m_unk0x13c = TRUE;
						AnimationManager()->FUN_10060570(TRUE);
						g_animationCalcStep = 0;
					}
					else {
						LegoWorld* world = CurrentWorld();
						if (world != NULL) {
							MxDSAction action;
							action.SetObjectId(1);
							action.SetAtomId(world->GetAtomId());
							LegoOmni::GetInstance()->Start(&action);
						}
					}
					break;
				case 'C':
					g_locationCalcStep = 1;
					break;
				case 'D':
					m_unk0x60 = -1.0;
					break;
				case 'F':
					RealtimeView::SetUserMaxLOD(0.0);
					break;
				case 'G':
					g_switchAct = TRUE;
					break;
				case 'H':
					RealtimeView::SetUserMaxLOD(5.0);
					break;
				case 'I': {
					LegoROI* roi = VideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateX(0.2618f);
					roi->WrappedVTable0x24(mat);
					break;
				}
				case 'J': {
					LegoROI* roi = VideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateZ(0.2618f);
					roi->WrappedVTable0x24(mat);
					break;
				}
				case 'K': {
					MxMatrix mat;
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					mat.SetIdentity();
					mat.RotateZ(-0.2618f);
					roi->WrappedVTable0x24(mat);
					break;
				}
				case 'L':
					g_changeLight = TRUE;
					break;
				case 'M': {
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateX(-0.2618f);
					roi->WrappedVTable0x24(mat);
					break;
				}
				case 'N':
					if (VideoManager()) {
						VideoManager()->SetRender3D(!VideoManager()->GetRender3D());
					}
					break;
				case 'P':
					if (!g_resetPlants) {
						PlantManager()->LoadWorldInfo(LegoOmni::e_act1);
						g_resetPlants = TRUE;
					}
					else {
						PlantManager()->Reset(LegoOmni::e_act1);
						g_resetPlants = FALSE;
					}
					break;
				case 'S':
					g_enableMusic = g_enableMusic == FALSE;
					BackgroundAudioManager()->Enable(g_enableMusic);
					break;
				case 'U':
					m_unk0x60 = 1.0;
					break;
				case 'V':
					if (g_nextAnimation > 0 && g_animationCalcStep == 0) {
						AnimationManager()->FUN_10061010(FALSE);
					}

					if (g_animationCalcStep != 0) {
						g_unk0x100f66bc = LegoAnimationManager::e_unk2;
					}

					g_nextAnimation = 0;
					g_animationCalcStep = 1;
					break;
				case 'W': {
					MxMatrix mat;
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					const float* position = roi->GetWorldPosition();
					const float* direction = roi->GetWorldDirection();
					const float* up = roi->GetWorldUp();

					MxTrace(
						"pos: %f, %f, %f\ndir: %f, %f, %f\nup: %f, %f, %f\n",
						EXPAND3(position),
						EXPAND3(direction),
						EXPAND3(up)
					);
					break;
				}
				case 'X':
					RealtimeView::SetUserMaxLOD(3.6);
					break;
				case 'j': {
					MxU8 newActor = GameState()->GetActorId() + 1;

					if (newActor > LegoActor::c_laura) {
						newActor = LegoActor::c_pepper;
					}

					GameState()->SetActorId(newActor);
					break;
				}
				case 'o':
					GameState()->SetActorId(LegoActor::c_brickster);
					break;
				case 'z':
					if (GameState()->m_isDirty) {
						GameState()->m_isDirty = FALSE;
					}
					else {
						GameState()->m_isDirty = TRUE;
					}
					break;
				case 0xbd:
					g_unk0x100f66bc = LegoAnimationManager::e_unk1;
					break;
				}
			}
			else {
				if (*g_currentInput == ((LegoEventNotificationParam&) p_param).GetKey()) {
					g_currentInput++;
				}
				else {
					g_currentInput = g_debugPassword;
				}
			}
		}
	}

	return 0;
}
