#include "MainDlg.h"

#include "AboutDlg.h"
#include "config.h"
#include "res/resource.h"

#include <assert.h>
#include <mxdirectx/legodxinfo.h>

DECOMP_SIZE_ASSERT(CDialog, 0x60)
DECOMP_SIZE_ASSERT(CMainDialog, 0x70)

// FUNCTION: CONFIG 0x00403d50
// FUNCTION: CONFIGD 0x004086f7
CMainDialog::CMainDialog(CWnd* pParent) : CDialog(IDD, pParent)
{
	m_icon = currentConfigApp->LoadIcon(IDI_CONFIG);
}

// FUNCTION: CONFIG 0x00403e50
// FUNCTION: CONFIGD 0x00408785
void CMainDialog::DoDataExchange(CDataExchange* pDX)
{
	CWnd::DoDataExchange(pDX);
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
// FUNCTION: CONFIGD 0x004087d9
BOOL CMainDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	SwitchToAdvanced(FALSE);
	CMenu* system_menu = CWnd::GetSystemMenu(FALSE);
	CString about_text;
	about_text.LoadString(IDS_ABOUT);
	if (!about_text.IsEmpty()) {
		system_menu->AppendMenu(MF_SEPARATOR, 0, (LPCTSTR) NULL);
		system_menu->AppendMenu(MF_STRING, 16, (LPCTSTR) about_text);
	}

	CWnd::SetIcon(m_icon, TRUE);
	CWnd::SetIcon(m_icon, FALSE);

	LegoDeviceEnumerate* info = currentConfigApp->m_dxInfo;
	assert(info);

	info->FUN_1009d210();
	m_modified = currentConfigApp->ReadRegisterSettings();
	CListBox* list_3d_devices = (CListBox*) GetDlgItem(IDC_LIST_3DDEVICES);
	int driver_i = 0;
	int device_i = 0;
	int selected = 0;

	for (list<MxDriver>::iterator it_driver = info->m_ddInfo.begin(); it_driver != info->m_ddInfo.end();
		 it_driver++, driver_i++) {
		const MxDriver& driver = *it_driver;

		for (list<Direct3DDeviceInfo>::const_iterator it_device = driver.m_devices.begin();
			 it_device != driver.m_devices.end();
			 it_device++) {

			if (&(*it_device) == currentConfigApp->m_d3dInfo) {
				selected = device_i;
			}

			char device_name[256];
			if (driver_i == 0) {
				sprintf(device_name, "%s ( Primary Device )", (*it_device).m_deviceName);
			}
			else {
				sprintf(device_name, "%s ( Secondary Device )", (*it_device).m_deviceName);
			}

			list_3d_devices->AddString(device_name);
			device_i += 1;
		}
	}

	list_3d_devices->SetCurSel(selected);
	UpdateInterface();
	return TRUE;
}

// FUNCTION: CONFIG 0x00404080
// FUNCTION: CONFIGD 0x00408ab7
void CMainDialog::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xfff0) == 0x10) {
		CAboutDialog about_dialog;
		about_dialog.DoModal();
	}
	else {
		CWnd::OnSysCommand(nID, lParam);
	}
}

// FUNCTION: CONFIG 0x00404150
// FUNCTION: CONFIGD 0x00408b49
void CMainDialog::OnPaint()
{
	if (IsIconic()) {
		CPaintDC painter(this);
		CWnd::SendMessage(WM_ICONERASEBKGND, (WPARAM) painter.GetSafeHdc(), 0);

		int iconWidth = GetSystemMetrics(SM_CXICON);
		int iconHeight = GetSystemMetrics(SM_CYICON);

		CRect dim;
		GetClientRect(&dim);

		int x = (dim.Width() - iconWidth + 1) / 2;
		int y = (dim.Height() - iconHeight + 1) / 2;

		painter.DrawIcon(x, y, m_icon);
	}
	else {
		CWnd::OnPaint();
	}
}

// FUNCTION: CONFIG 0x00404230
// FUNCTION: CONFIGD 0x00408c61
HCURSOR CMainDialog::OnQueryDragIcon()
{
	return m_icon;
}

// FUNCTION: CONFIG 0x00404240
// FUNCTION: CONFIGD 0x00408c7d
void CMainDialog::OnList3DevicesSelectionChanged()
{
	CConfigApp* app = currentConfigApp;
	assert(app);

	LegoDeviceEnumerate* device_enumerator = app->m_dxInfo;
	assert(device_enumerator);

	CListBox* listbox = (CListBox*) GetDlgItem(IDC_LIST_3DDEVICES);
	int selected = listbox->GetCurSel();
	int r = device_enumerator->GetDevice(selected, app->m_ddInfo, app->m_d3dInfo);
	assert(r == 0);

	if (!currentConfigApp->GetHardwareDeviceColorModel()) {
		currentConfigApp->m_3d_video_ram = FALSE;
		currentConfigApp->m_flip_surfaces = FALSE;
		CheckDlgButton(IDC_CHK_3D_VIDEO_MEMORY, currentConfigApp->m_3d_video_ram);
		CheckDlgButton(IDC_CHK_FLIP_VIDEO_MEM_PAGES, currentConfigApp->m_flip_surfaces);
	}
	else {
		GetDlgItem(IDC_CHK_DRAW_CURSOR)->EnableWindow(TRUE);
	}

	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404320
// FUNCTION: CONFIGD 0x00408d79
void CMainDialog::OnCancel()
{
	CDialog::OnCancel();
}

// FUNCTION: CONFIG 0x00404330
// FUNCTION: CONFIGD 0x00408de5
void CMainDialog::OnDestroy()
{
	CWnd::OnDestroy();
}

// FUNCTION: CONFIG 0x00404340
// FUNCTION: CONFIGD 0x00408e03
void CMainDialog::OnButtonCancel()
{
	if (m_modified) {
		currentConfigApp->WriteRegisterSettings();
	}
	CDialog::OnCancel();
}

// FUNCTION: CONFIG 0x00404360
// FUNCTION: CONFIGD 0x00408e2f
void CMainDialog::UpdateInterface()
{
	currentConfigApp->ValidateSettings();
	BOOL flip_surfaces = currentConfigApp->m_flip_surfaces;

	BOOL enable3d = !flip_surfaces && !currentConfigApp->GetHardwareDeviceColorModel();
	GetDlgItem(IDC_CHK_3D_VIDEO_MEMORY)->EnableWindow(enable3d);

	CheckDlgButton(IDC_CHK_FLIP_VIDEO_MEM_PAGES, flip_surfaces);
	CheckDlgButton(IDC_CHK_3D_VIDEO_MEMORY, currentConfigApp->m_3d_video_ram);
	BOOL full_screen = currentConfigApp->m_full_screen;
	currentConfigApp->AdjustDisplayBitDepthBasedOnRenderStatus();

	if (currentConfigApp->GetHardwareDeviceColorModel()) {
		CheckDlgButton(IDC_CHK_DRAW_CURSOR, TRUE);
	}
	else {
		CheckDlgButton(IDC_CHK_DRAW_CURSOR, FALSE);
		currentConfigApp->m_draw_cursor = FALSE;
		GetDlgItem(IDC_CHK_DRAW_CURSOR)->EnableWindow(FALSE);
	}

	if (full_screen) {
		if (currentConfigApp->m_display_bit_depth == 8) {
			CheckRadioButton(IDC_RAD_PALETTE_256, IDC_RAD_PALETTE_16BIT, IDC_RAD_PALETTE_256);
		}
		else {
			CheckRadioButton(IDC_RAD_PALETTE_256, IDC_RAD_PALETTE_16BIT, IDC_RAD_PALETTE_16BIT);
		}
	}
	else {
		CheckDlgButton(IDC_RAD_PALETTE_256, 0);
		CheckDlgButton(IDC_RAD_PALETTE_16BIT, 0);
		currentConfigApp->m_display_bit_depth = 0;
	}

	BOOL enable256 = full_screen && currentConfigApp->GetConditionalDeviceRenderBitDepth() != 0;
	GetDlgItem(IDC_RAD_PALETTE_256)->EnableWindow(enable256);

	BOOL enable16 = full_screen && currentConfigApp->GetDeviceRenderBitStatus() != 0;
	GetDlgItem(IDC_RAD_PALETTE_16BIT)->EnableWindow(enable16);

	CheckDlgButton(IDC_CHK_3DSOUND, currentConfigApp->m_3d_sound);
	CheckDlgButton(IDC_CHK_DRAW_CURSOR, currentConfigApp->m_draw_cursor);

	switch (currentConfigApp->m_model_quality) {
	// DECOMP: case 0 removed for retail.
	case 1:
		CheckRadioButton(IDC_RAD_MODEL_QUALITY_LOW, IDC_RAD_MODEL_QUALITY_HIGH, IDC_RAD_MODEL_QUALITY_LOW);
		break;
	case 2:
		CheckRadioButton(IDC_RAD_MODEL_QUALITY_LOW, IDC_RAD_MODEL_QUALITY_HIGH, IDC_RAD_MODEL_QUALITY_HIGH);
		break;
	}

	if (currentConfigApp->m_texture_quality == 0) {
		CheckRadioButton(IDC_RAD_TEXTURE_QUALITY_LOW, IDC_RAD_TEXTURE_QUALITY_HIGH, IDC_RAD_TEXTURE_QUALITY_LOW);
	}
	else {
		CheckRadioButton(IDC_RAD_TEXTURE_QUALITY_LOW, IDC_RAD_TEXTURE_QUALITY_HIGH, IDC_RAD_TEXTURE_QUALITY_HIGH);
	}

	CheckDlgButton(IDC_CHK_JOYSTICK, currentConfigApp->m_use_joystick);
	CheckDlgButton(IDC_CHK_MUSIC, currentConfigApp->m_music);
}

// STUB: CONFIGD 0x00409152
void CMainDialog::OnCheckboxWideAngle()
{
	// DECOMP: m_wide_angle member removed for retail.
	// currentConfigApp->m_wide_angle = IsDlgButtonChecked(IDC_CHK_WIDE_ANGLE);
	// m_modified = TRUE;
	// UpdateInterface();
}

// FUNCTION: CONFIG 0x004045e0
// FUNCTION: CONFIGD 0x00409198
void CMainDialog::OnCheckbox3DSound()
{
	currentConfigApp->m_3d_sound = IsDlgButtonChecked(IDC_CHK_3DSOUND);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404610
// FUNCTION: CONFIGD 0x004091de
void CMainDialog::OnCheckbox3DVideoMemory()
{
	currentConfigApp->m_3d_video_ram = IsDlgButtonChecked(IDC_CHK_3D_VIDEO_MEMORY);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404640
// FUNCTION: CONFIGD 0x00409224
void CMainDialog::OnRadiobuttonPalette16bit()
{
	currentConfigApp->m_display_bit_depth = 16;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404670
// FUNCTION: CONFIGD 0x00409261
void CMainDialog::OnRadiobuttonPalette256()
{
	currentConfigApp->m_display_bit_depth = 8;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004046a0
// FUNCTION: CONFIGD 0x0040929e
void CMainDialog::OnCheckboxFlipVideoMemPages()
{
	currentConfigApp->m_flip_surfaces = IsDlgButtonChecked(IDC_CHK_FLIP_VIDEO_MEM_PAGES);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIGD 0x004092e4
void CMainDialog::OnCheckboxFullScreen()
{
	currentConfigApp->m_full_screen = IsDlgButtonChecked(IDC_CHK_FULL_SCREEN);
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIGD 0x0040932a
void CMainDialog::OnRadiobuttonModelLowestQuality()
{
	currentConfigApp->m_model_quality = 0;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x004046d0
// FUNCTION: CONFIGD 0x00409367
void CMainDialog::OnRadiobuttonModelLowQuality()
{
	currentConfigApp->m_model_quality = 1;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404700
// FUNCTION: CONFIGD 0x004093a4
void CMainDialog::OnRadiobuttonModelHighQuality()
{
	currentConfigApp->m_model_quality = 2;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404730
// FUNCTION: CONFIGD 0x004093e1
void CMainDialog::OnRadiobuttonTextureLowQuality()
{
	currentConfigApp->m_texture_quality = 0;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404760
// FUNCTION: CONFIGD 0x0040941e
void CMainDialog::OnRadiobuttonTextureHighQuality()
{
	currentConfigApp->m_texture_quality = 1;
	m_modified = TRUE;
	UpdateInterface();
}

// FUNCTION: CONFIG 0x00404790
// FUNCTION: CONFIGD 0x0040945b
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
	CWnd::GetWindowRect(&dialog_rect);
	GetDlgItem(IDC_GRP_ADVANCED)->GetWindowRect(&grp_advanced_rect);
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
