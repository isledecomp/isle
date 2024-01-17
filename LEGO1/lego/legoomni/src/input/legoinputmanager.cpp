#include "legoinputmanager.h"

#include "legocontrolmanager.h"
#include "legoomni.h"
#include "mxautolocker.h"

DECOMP_SIZE_ASSERT(LegoInputManager, 0x338);
DECOMP_SIZE_ASSERT(LegoEventQueue, 0x18);

// GLOBAL: LEGO1 0x100f31b0
MxS32 g_unk0x100f31b0 = -1;

// GLOBAL: LEGO1 0x100f31b4
MxS32 g_unk0x100f31b4 = 0;

// FUNCTION: LEGO1 0x1005b790
LegoInputManager::LegoInputManager()
{
	m_unk0x5c = NULL;
	m_world = NULL;
	m_camera = NULL;
	m_eventQueue = NULL;
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

// STUB: LEGO1 0x1005b8b0
MxResult LegoInputManager::Tickle()
{
	ProcessEvents();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005b8f0
LegoInputManager::~LegoInputManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x1005b960
MxResult LegoInputManager::Create(HWND p_hwnd)
{
	// TODO
	if (m_eventQueue == NULL)
		m_eventQueue = new LegoEventQueue();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005bfe0
void LegoInputManager::Destroy()
{
	ReleaseDX();

	if (m_unk0x5c)
		delete m_unk0x5c;
	m_unk0x5c = NULL;

	if (m_eventQueue)
		delete m_eventQueue;
	m_eventQueue = NULL;

	if (m_controlManager)
		delete m_controlManager;
}

// FUNCTION: LEGO1 0x1005c030
void LegoInputManager::CreateAndAcquireKeyboard(HWND p_hwnd)
{
	HINSTANCE hinstance = (HINSTANCE) GetWindowLong(p_hwnd, GWL_HINSTANCE);
	HRESULT hresult = DirectInputCreate(hinstance, 0x500, &m_directInput, NULL); // 0x500 for DX5

	if (hresult == DI_OK) {
		HRESULT createdeviceresult = m_directInput->CreateDevice(GUID_SysKeyboard, &m_directInputDevice, NULL);
		if (createdeviceresult == DI_OK) {
			m_directInputDevice->SetCooperativeLevel(p_hwnd, DISCL_NONEXCLUSIVE | DISCL_FOREGROUND);
			m_directInputDevice->SetDataFormat(&c_dfDIKeyboard);
			m_directInputDevice->Acquire();
		}
	}
}

// FUNCTION: LEGO1 0x1005c0a0
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

// FUNCTION: LEGO1 0x1005c240
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

// FUNCTION: LEGO1 0x1005c320
MxResult LegoInputManager::GetJoystickState(
	MxU32* p_joystickX,
	MxU32* p_joystickY,
	DWORD* p_buttonsState,
	MxU32* p_povPosition
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
			*p_buttonsState = joyinfoex.dwButtons;
			MxU32 xmin = m_joyCaps.wXmin;
			MxU32 ymax = m_joyCaps.wYmax;
			MxU32 ymin = m_joyCaps.wYmin;
			MxS32 ydiff = ymax - ymin;
			*p_joystickX = ((joyinfoex.dwXpos - xmin) * 100) / (m_joyCaps.wXmax - xmin);
			*p_joystickY = ((joyinfoex.dwYpos - m_joyCaps.wYmin) * 100) / ydiff;
			if ((m_joyCaps.wCaps & (JOYCAPS_POV4DIR | JOYCAPS_POVCTS)) != 0) {
				if (joyinfoex.dwPOV == JOY_POVCENTERED) {
					*p_povPosition = (MxU32) -1;
					return SUCCESS;
				}
				*p_povPosition = joyinfoex.dwPOV / 100;
				return SUCCESS;
			}
			else {
				*p_povPosition = (MxU32) -1;
				return SUCCESS;
			}
		}
	}
	return FAILURE;
}

// STUB: LEGO1 0x1005c470
void LegoInputManager::Register(MxCore*)
{
	// TODO
}

// STUB: LEGO1 0x1005c5c0
void LegoInputManager::UnRegister(MxCore*)
{
	// TODO
}

// FUNCTION: LEGO1 0x1005c700
void LegoInputManager::SetCamera(LegoCameraController* p_camera)
{
	m_camera = p_camera;
}

// FUNCTION: LEGO1 0x1005c710
void LegoInputManager::ClearCamera()
{
	m_camera = NULL;
}

// FUNCTION: LEGO1 0x1005c720
void LegoInputManager::SetWorld(LegoWorld* p_world)
{
	m_world = p_world;
}

// FUNCTION: LEGO1 0x1005c730
void LegoInputManager::ClearWorld()
{
	m_world = NULL;
}

// FUNCTION: LEGO1 0x1005c740
void LegoInputManager::QueueEvent(NotificationId p_id, MxU8 p_modifier, MxLong p_x, MxLong p_y, MxU8 p_key)
{
	LegoEventNotificationParam param = LegoEventNotificationParam(p_id, NULL, p_modifier, p_x, p_y, p_key);

	if (((!m_unk0x88) || ((m_unk0x335 && (param.GetType() == c_notificationButtonDown)))) ||
		((m_unk0x336 && (p_key == ' ')))) {
		ProcessOneEvent(param);
	}
}

// FUNCTION: LEGO1 0x1005c820
void LegoInputManager::ProcessEvents()
{
	MxAutoLocker lock(&m_criticalSection);

	LegoEventNotificationParam event;
	while (m_eventQueue->Dequeue(event)) {
		if (ProcessOneEvent(event))
			break;
	}
}

// STUB: LEGO1 0x1005c9c0
MxBool LegoInputManager::ProcessOneEvent(LegoEventNotificationParam& p_param)
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x1005cfb0
void LegoInputManager::SetTimer()
{
	LegoOmni* omni = LegoOmni::GetInstance();
	UINT timer = ::SetTimer(omni->GetWindowHandle(), 1, m_timeout, NULL);
	m_timer = timer;
}

// FUNCTION: LEGO1 0x1005cfd0
void LegoInputManager::KillTimer()
{
	if (m_timer != 0) {
		LegoOmni* omni = LegoOmni::GetInstance();
		::KillTimer(omni->GetWindowHandle(), m_timer);
	}
}

// FUNCTION: LEGO1 0x1005cff0
void LegoInputManager::EnableInputProcessing()
{
	m_unk0x88 = FALSE;
	g_unk0x100f31b0 = -1;
	g_unk0x100f31b4 = 0;
}
