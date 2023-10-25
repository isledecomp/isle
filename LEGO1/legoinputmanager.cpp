#include "legoinputmanager.h"

#include "legocontrolmanager.h"
#include "legoomni.h"
#include "mxautolocker.h"

DECOMP_SIZE_ASSERT(LegoInputManager, 0x338);

// OFFSET: LEGO1 0x1005b790
LegoInputManager::LegoInputManager()
{
	m_eventQueue = NULL;
	m_world = NULL;
	m_camera = NULL;
	m_unk0x68 = NULL;
	m_unk0x80 = 0;
	m_timer = 0;
	m_unk0x6c = 0;
	m_unk0x70 = 0;
	m_controlManager = NULL;
	m_unk0x81 = 0;
	m_unk0x88 = FALSE;
	m_directInput = NULL;
	m_directInputDevice = NULL;
	m_unk0x94 = 0;
	m_unk0x195 = 0;
	m_joyid = -1;
	m_joystickIndex = -1;
	m_useJoystick = FALSE;
	m_unk0x335 = FALSE;
	m_unk0x336 = FALSE;
	m_unk0x74 = 0x19;
	m_timeout = 1000;
}

// OFFSET: LEGO1 0x1005b8b0 STUB
MxResult LegoInputManager::Tickle()
{
	// TODO
	return SUCCESS;
}

// OFFSET: LEGO1 0x1005b8f0
LegoInputManager::~LegoInputManager()
{
	Destroy();
}

// OFFSET: LEGO1 0x1005bfe0
void LegoInputManager::Destroy()
{
	ReleaseDX();

	if (m_eventQueue)
		delete m_eventQueue;
	m_eventQueue = NULL;

	if (m_unk0x68)
		delete m_unk0x68;
	m_unk0x68 = NULL;

	if (m_controlManager)
		delete m_controlManager;
}

// OFFSET: LEGO1 0x1005c030
void LegoInputManager::CreateAndAcquireKeyboard(HWND hwnd)
{
	HINSTANCE hinstance = (HINSTANCE) GetWindowLong(hwnd, GWL_HINSTANCE);
	HRESULT hresult = DirectInputCreate(hinstance, 0x500, &m_directInput, NULL); // 0x500 for DX5

	if (hresult == DI_OK) {
		HRESULT createdeviceresult = m_directInput->CreateDevice(GUID_SysKeyboard, &m_directInputDevice, NULL);
		if (createdeviceresult == DI_OK) {
			m_directInputDevice->SetCooperativeLevel(hwnd, DISCL_NONEXCLUSIVE | DISCL_FOREGROUND);
			m_directInputDevice->SetDataFormat(&c_dfDIKeyboard);
			m_directInputDevice->Acquire();
		}
	}
}

// OFFSET: LEGO1 0x1005c0a0
void LegoInputManager::ReleaseDX()
{
	if (m_directInputDevice != NULL) {
		m_directInputDevice->Unacquire();
		m_directInputDevice->Release();
		m_directInputDevice = NULL;
	}

	if (m_directInput != NULL) {
		m_directInput->Release();
		m_directInput = NULL;
	}
}

// OFFSET: LEGO1 0x1005c240
MxResult LegoInputManager::GetJoystickId()
{
	JOYINFOEX joyinfoex;

	if (m_useJoystick != FALSE) {
		MxS32 joyid = m_joystickIndex;
		if (joyid >= 0) {
			joyinfoex.dwSize = 0x34;
			joyinfoex.dwFlags = 0xFF;

			if (joyGetPosEx(joyid, &joyinfoex) == JOYERR_NOERROR &&
				joyGetDevCaps(joyid, &m_joyCaps, 0x194) == JOYERR_NOERROR) {
				m_joyid = joyid;
				return SUCCESS;
			}
		}

		for (joyid = JOYSTICKID1; joyid < 16; joyid++) {
			joyinfoex.dwSize = 0x34;
			joyinfoex.dwFlags = 0xFF;
			if (joyGetPosEx(joyid, &joyinfoex) == JOYERR_NOERROR &&
				joyGetDevCaps(joyid, &m_joyCaps, 0x194) == JOYERR_NOERROR) {
				m_joyid = joyid;
				return SUCCESS;
			}
		}
	}

	return FAILURE;
}

// OFFSET: LEGO1 0x1005c320
MxResult LegoInputManager::GetJoystickState(
	MxU32* joystick_x,
	MxU32* joystick_y,
	DWORD* buttons_state,
	MxU32* pov_position
)
{
	if (m_useJoystick != FALSE) {
		if (m_joyid < 0 && GetJoystickId() == -1) {
			m_useJoystick = FALSE;
			return FAILURE;
		}

		JOYINFOEX joyinfoex;
		joyinfoex.dwSize = 0x34;
		joyinfoex.dwFlags = JOY_RETURNX | JOY_RETURNY | JOY_RETURNBUTTONS;
		MxU32 capabilities = m_joyCaps.wCaps;

		if ((capabilities & JOYCAPS_HASPOV) != 0) {
			joyinfoex.dwFlags = JOY_RETURNX | JOY_RETURNY | JOY_RETURNPOV | JOY_RETURNBUTTONS;

			if ((capabilities & JOYCAPS_POVCTS) != 0)
				joyinfoex.dwFlags = JOY_RETURNX | JOY_RETURNY | JOY_RETURNPOV | JOY_RETURNBUTTONS | JOY_RETURNPOVCTS;
		}

		MMRESULT mmresult = joyGetPosEx(m_joyid, &joyinfoex);

		if (mmresult == MMSYSERR_NOERROR) {
			*buttons_state = joyinfoex.dwButtons;
			MxU32 xmin = m_joyCaps.wXmin;
			MxU32 ymax = m_joyCaps.wYmax;
			MxU32 ymin = m_joyCaps.wYmin;
			MxS32 ydiff = ymax - ymin;
			*joystick_x = ((joyinfoex.dwXpos - xmin) * 100) / (m_joyCaps.wXmax - xmin);
			*joystick_y = ((joyinfoex.dwYpos - m_joyCaps.wYmin) * 100) / ydiff;
			if ((m_joyCaps.wCaps & (JOYCAPS_POV4DIR | JOYCAPS_POVCTS)) != 0) {
				if (joyinfoex.dwPOV == JOY_POVCENTERED) {
					*pov_position = (MxU32) -1;
					return SUCCESS;
				}
				*pov_position = joyinfoex.dwPOV / 100;
				return SUCCESS;
			}
			else {
				*pov_position = (MxU32) -1;
				return SUCCESS;
			}
		}
	}
	return FAILURE;
}

// OFFSET: LEGO1 0x1005c470 STUB
void LegoInputManager::Register(MxCore*)
{
	// TODO
}

// OFFSET: LEGO1 0x1005c5c0 STUB
void LegoInputManager::UnRegister(MxCore*)
{
	// TODO
}

// OFFSET: LEGO1 0x1005c700
void LegoInputManager::SetCamera(LegoCameraController* p_camera)
{
	m_camera = p_camera;
}

// OFFSET: LEGO1 0x1005c710
void LegoInputManager::ClearCamera()
{
	m_camera = NULL;
}

// OFFSET: LEGO1 0x1005c720
void LegoInputManager::SetWorld(LegoWorld* p_world)
{
	m_world = p_world;
}

// OFFSET: LEGO1 0x1005c730
void LegoInputManager::ClearWorld()
{
	m_world = NULL;
}

// OFFSET: LEGO1 0x1005c740 STUB
void LegoInputManager::QueueEvent(NotificationId id, unsigned char p2, MxLong p3, MxLong p4, unsigned char p5)
{
	// TODO
}

// OFFSET: LEGO1 0x1005cfb0
void LegoInputManager::SetTimer()
{
	LegoOmni* omni = LegoOmni::GetInstance();
	UINT timer = ::SetTimer(omni->GetWindowHandle(), 1, m_timeout, NULL);
	m_timer = timer;
}

// OFFSET: LEGO1 0x1005cfd0
void LegoInputManager::KillTimer()
{
	if (m_timer != 0) {
		LegoOmni* omni = LegoOmni::GetInstance();
		::KillTimer(omni->GetWindowHandle(), m_timer);
	}
}
