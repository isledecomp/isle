#include "MainDlg.h"

#include "AboutDlg.h"
#include "config.h"
#include "res/resource.h"

#include <mxdirectx/mxdirect3d.h>

DECOMP_SIZE_ASSERT(CDialog, 0x60)
DECOMP_SIZE_ASSERT(CMainDialog, 0x70)

// FUNCTION: CONFIG 0x00403d50
CMainDialog::CMainDialog(CWnd* pParent) : CDialog(IDD, pParent)
{
	afxCurrentWinApp;
	m_icon = LoadIconA(AfxFindResourceHandle(MAKEINTRESOURCE(IDI_CONFIG), RT_GROUP_ICON), MAKEINTRESOURCE(IDI_CONFIG));
}

// FUNCTION: CONFIG 0x00403e50
void CMainDialog::DoDataExchange(CDataExchange* pDX)
{
}

BEGIN_MESSAGE_MAP(CMainDialog, CDialog)
ON_WM_SYSCOMMAND()
ON_WM_PAINT()
ON_WM_QUERYDRAGICON()
ON_COMMAND(IDC_CHK_FLIP_VIDEO_MEM_PAGES, OnCheckboxFlipVideoMemPages)
ON_LBN_SELCHANGE(IDC_LIST_3DDEVICES, OnList3DevicesSelectionChanged)
ON_COMMAND(IDC_RAD_PALETTE_16BIT, OnRadiobuttonPalette16bit)
ON_COMMAND(IDC_RAD_PALETTE_256, OnRadiobuttonPalette256)
ON_COMMAND(IDC_CHK_3D_VIDEO_MEMORY, OnCheckbox3DVideoMemory)
ON_WM_DESTROY() // FIXME: CONFIG.EXE calls Default
ON_COMMAND(IDABORT, OnButtonCancel)
ON_COMMAND(IDC_CHK_3DSOUND, OnCheckbox3DSound)
ON_COMMAND(IDC_RAD_MODEL_QUALITY_LOW, OnRadiobuttonModelLowQuality)
ON_COMMAND(IDC_RAD_MODEL_QUALITY_HIGH, OnRadiobuttonModelHighQuality)
ON_COMMAND(IDC_RAD_TEXTURE_QUALITY_LOW, OnRadiobuttonTextureLowQuality)
ON_COMMAND(IDC_RAD_TEXTURE_QUALITY_HIGH, OnRadiobuttonTextureHighQuality)
ON_COMMAND(IDC_CHK_JOYSTICK, OnCheckboxJoystick)
ON_COMMAND(IDC_BTN_ADVANCED, OnButtonAdvanced)
ON_COMMAND(IDC_CHK_DRAW_CURSOR, OnCheckboxDrawCursor)
ON_COMMAND(IDC_CHK_MUSIC, OnCheckboxMusic)
END_MESSAGE_MAP()

// FUNCTION: CONFIG 0x00403e80
BOOL CMainDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	SwitchToAdvanced(FALSE);
	CMenu* system_menu = CMenu::FromHandle(::GetSystemMenu(m_hWnd, FALSE));
	CString about_text;
	about_text.LoadString(IDS_ABOUT);
	if (system_menu) {
		AppendMenuA(system_menu->m_hMenu, MF_SEPARATOR, 0, NULL);
		AppendMenuA(system_menu->m_hMenu, MF_STRING, 16, (LPCTSTR) about_text);
	}
	SendMessage(WM_SETICON, ICON_BIG, (LPARAM) m_icon);
	SendMessage(WM_SETICON, ICON_SMALL, (LPARAM) m_icon);
	MxDeviceEnumerate* enumerator = currentConfigApp->m_device_enumerator;
	enumerator->FUN_1009d210();
	m_modified = currentConfigApp->ReadRegisterSettings();
	CWnd* list_3d_devices = GetDlgItem(IDC_LIST_3DDEVICES);
	int driver_i = 0;
	int device_i = 0;
	int selected = 0;
	char device_name[256];
	const list<MxDriver>& driver_list = enumerator->GetDriverList();
	for (list<MxDriver>::const_iterator it_driver = driver_list.begin(); it_driver != driver_list.end(); it_driver++) {
		const MxDriver& driver = *it_driver;
		for (list<Direct3DDeviceInfo>::const_iterator it_device = driver.m_devices.begin();
			 it_device != driver.m_devices.end();
			 it_device++) {
			const Direct3DDeviceInfo& device = *it_device;
			if (&device == currentConfigApp->m_device) {
				selected = device_i;
			}
			device_i += 1;
			sprintf(
				device_name,
				driver_i == 0 ? "%s ( Primary Device )" : "%s ( Secondary Device )",
				device.m_deviceName
			);
			::SendMessage(list_3d_devices->m_hWnd, LB_ADDSTRING, 0, (LPARAM) device_name);
		}
		driver_i += 1;
	}
	::SendMessage(list_3d_devices->m_hWnd, LB_SETCURSEL, selected, 0);
	UpdateInterface();
	return TRUE;
}

// FUNCTION: CONFIG 0x00404080
void CMainDialog::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xfff0) == 0x10) {
		CAboutDialog about_dialog;
		about_dialog.DoModal();
	}
	else {
		Default();
	}
}

// FUNCTION: CONFIG 0x00404150
void CMainDialog::OnPaint()
{
	if (IsIconic()) {
		CPaintDC painter(this);
		::SendMessage(m_hWnd, WM_ICONERASEBKGND, (WPARAM) painter.m_hDC, 0);
		RECT dim;
		GetClientRect(&dim);
		DrawIcon(
			painter.m_hDC,
			(dim.right - dim.left - GetSystemMetrics(SM_CXICON) + 1) / 2,
			(dim.bottom - dim.top - GetSystemMetrics(SM_CYICON) + 1) / 2,
			m_icon
		);
	}
	else {
		Default();
	}
}

// FUNCTION: CONFIG 0x00404230
HCURSOR CMainDialog::OnQueryDragIcon()
{
	return m_icon;
}

// FUNCTION: CONFIG 0x00404240
void CMainDialog::OnList3DevicesSelectionChanged()
{
	MxDeviceEnumerate* device_enumerator = currentConfigApp->m_device_enumerator;
	int selected = ::SendMessage(GetDlgItem(IDC_LIST_3DDEVICES)->m_hWnd, LB_GETCURSEL, 0, 0);
	device_enumerator->GetDevice(selected, currentConfigApp->m_driver, currentConfigApp->m_device);
	if (currentConfigApp->GetHardwareDeviceColorModel()) {
		GetDlgItem(IDC_CHK_DRAW_CURSOR)->EnableWindow(TRUE);
	}
	else {
		currentConfigApp->m_3d_video_ram = FALSE;
		currentConfigApp->m_flip_surfaces = FALSE;
		CheckDlgButton(IDC_CHK_3D_VIDEO_MEMORY, currentConfigApp->m_3d_video_ram);
		CheckDlgButton(IDC_CHK_FLIP_VIDEO_MEM_PAGES, currentConfigApp->m_flip_surfaces);
	}
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404320
void CMainDialog::OnCancel()
{
	CDialog::OnCancel();
}

// FUNCTION: CONFIG 0x00404330
void CMainDialog::OnDestroy()
{
	CDialog::Default();
}

// FUNCTION: CONFIG 0x00404340
void CMainDialog::OnButtonCancel()
{
	if (m_modified) {
		currentConfigApp->WriteRegisterSettings();
	}
	OnCancel();
}

// FUNCTION: CONFIG 0x00404360
void CMainDialog::UpdateInterface()
{
	currentConfigApp->ValidateSettings();
	GetDlgItem(IDC_CHK_3D_VIDEO_MEMORY)
		->EnableWindow(!currentConfigApp->m_flip_surfaces && !currentConfigApp->GetHardwareDeviceColorModel());
	CheckDlgButton(IDC_CHK_FLIP_VIDEO_MEM_PAGES, currentConfigApp->m_flip_surfaces);
	CheckDlgButton(IDC_CHK_3D_VIDEO_MEMORY, currentConfigApp->m_3d_video_ram);
	BOOL full_screen = currentConfigApp->m_full_screen;
	currentConfigApp->FUN_00403810();
	if (currentConfigApp->GetHardwareDeviceColorModel()) {
		CheckDlgButton(IDC_CHK_DRAW_CURSOR, TRUE);
	}
	else {
		CheckDlgButton(IDC_CHK_DRAW_CURSOR, FALSE);
		currentConfigApp->m_draw_cursor = FALSE;
		GetDlgItem(IDC_CHK_DRAW_CURSOR)->EnableWindow(FALSE);
	}
	if (full_screen) {
		CheckRadioButton(
			IDC_RAD_PALETTE_256,
			IDC_RAD_PALETTE_16BIT,
			currentConfigApp->m_display_bit_depth == 8 ? IDC_RAD_PALETTE_256 : IDC_RAD_PALETTE_16BIT
		);
	}
	else {
		CheckDlgButton(IDC_RAD_PALETTE_256, 0);
		CheckDlgButton(IDC_RAD_PALETTE_16BIT, 0);
		currentConfigApp->m_display_bit_depth = 0;
	}
	GetDlgItem(IDC_RAD_PALETTE_256)->EnableWindow(full_screen && currentConfigApp->FUN_004037a0());
	GetDlgItem(IDC_RAD_PALETTE_16BIT)->EnableWindow(full_screen && currentConfigApp->FUN_004037e0());
	CheckDlgButton(IDC_CHK_3DSOUND, currentConfigApp->m_3d_sound);
	CheckDlgButton(IDC_CHK_DRAW_CURSOR, currentConfigApp->m_draw_cursor);
	switch (currentConfigApp->m_model_quality) {
	case 1:
		CheckRadioButton(IDC_RAD_MODEL_QUALITY_LOW, IDC_RAD_MODEL_QUALITY_HIGH, IDC_RAD_MODEL_QUALITY_LOW);
		break;
	case 2:
		CheckRadioButton(IDC_RAD_MODEL_QUALITY_LOW, IDC_RAD_MODEL_QUALITY_HIGH, IDC_RAD_MODEL_QUALITY_HIGH);
		break;
	}
	CheckRadioButton(
		IDC_RAD_TEXTURE_QUALITY_LOW,
		IDC_RAD_TEXTURE_QUALITY_HIGH,
		currentConfigApp->m_texture_quality == 0 ? IDC_RAD_TEXTURE_QUALITY_LOW : IDC_RAD_TEXTURE_QUALITY_HIGH
	);
	CheckDlgButton(IDC_CHK_JOYSTICK, currentConfigApp->m_use_joystick);
	CheckDlgButton(IDC_CHK_MUSIC, currentConfigApp->m_music);
}

// FUNCTION: CONFIG 0x004045e0
void CMainDialog::OnCheckbox3DSound()
{
	currentConfigApp->m_3d_sound = IsDlgButtonChecked(IDC_CHK_3DSOUND);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404610
void CMainDialog::OnCheckbox3DVideoMemory()
{
	currentConfigApp->m_3d_video_ram = IsDlgButtonChecked(IDC_CHK_3D_VIDEO_MEMORY);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404640
void CMainDialog::OnRadiobuttonPalette16bit()
{
	currentConfigApp->m_display_bit_depth = 16;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404670
void CMainDialog::OnRadiobuttonPalette256()
{
	currentConfigApp->m_display_bit_depth = 8;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004046a0
void CMainDialog::OnCheckboxFlipVideoMemPages()
{
	currentConfigApp->m_flip_surfaces = IsDlgButtonChecked(IDC_CHK_FLIP_VIDEO_MEM_PAGES);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004046d0
void CMainDialog::OnRadiobuttonModelLowQuality()
{
	currentConfigApp->m_model_quality = 1;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404700
void CMainDialog::OnRadiobuttonModelHighQuality()
{
	currentConfigApp->m_model_quality = 2;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404730
void CMainDialog::OnRadiobuttonTextureLowQuality()
{
	currentConfigApp->m_texture_quality = 0;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404760
void CMainDialog::OnRadiobuttonTextureHighQuality()
{
	currentConfigApp->m_texture_quality = 1;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404790
void CMainDialog::OnCheckboxJoystick()
{
	currentConfigApp->m_use_joystick = IsDlgButtonChecked(IDC_CHK_JOYSTICK);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004047c0
void CMainDialog::OnButtonAdvanced()
{
	SwitchToAdvanced(!m_advanced);
}

// FUNCTION: CONFIG 0x004047d0
void CMainDialog::SwitchToAdvanced(BOOL p_advanced)
{
	RECT dialog_rect;
	RECT grp_advanced_rect;
	::GetWindowRect(m_hWnd, &dialog_rect);
	::GetWindowRect(GetDlgItem(IDC_GRP_ADVANCED)->m_hWnd, &grp_advanced_rect);
	CWnd* button_advanced = GetDlgItem(IDC_BTN_ADVANCED);
	m_advanced = p_advanced;
	int height;
	if (p_advanced) {
		height = grp_advanced_rect.bottom - dialog_rect.top + 10;
		GetDlgItem(IDC_BMP_SHARK)->EnableWindow(TRUE);
		button_advanced->SetWindowText("Basic");
	}
	else {
		height = grp_advanced_rect.top - dialog_rect.top;
		GetDlgItem(IDC_BMP_SHARK)->EnableWindow(FALSE);
		button_advanced->SetWindowText("Advanced");
	}
	SetWindowPos(&wndTop, 0, 0, dialog_rect.right - dialog_rect.left, height, SWP_NOMOVE);
}

// FUNCTION: CONFIG 0x00404890
void CMainDialog::OnCheckboxDrawCursor()
{
	currentConfigApp->m_draw_cursor = IsDlgButtonChecked(IDC_CHK_DRAW_CURSOR);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004048c0
void CMainDialog::OnCheckboxMusic()
{
	currentConfigApp->m_music = IsDlgButtonChecked(IDC_CHK_MUSIC);
	m_modified = TRUE;
	UpdateInterface();
}
