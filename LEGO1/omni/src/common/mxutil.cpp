#include "mxutil.h"

#include "mxcompositepresenter.h"
#include "mxdsaction.h"
#include "mxdsactionlist.h"
#include "mxdsfile.h"
#include "mxdsmultiaction.h"
#include "mxdsobject.h"
#include "mxpresenterlist.h"
#include "mxrect32.h"

// GLOBAL: LEGO1 0x101020e8
void (*g_omniUserMessage)(const char*, int) = NULL;

// FUNCTION: LEGO1 0x100b6e10
MxBool GetRectIntersection(
	MxS32 p_rect1Width,
	MxS32 p_rect1Height,
	MxS32 p_rect2Width,
	MxS32 p_rect2Height,
	MxS32* p_rect1Left,
	MxS32* p_rect1Top,
	MxS32* p_rect2Left,
	MxS32* p_rect2Top,
	MxS32* p_width,
	MxS32* p_height
)
{
	MxPoint32 rect1Origin(*p_rect1Left, *p_rect1Top);
	MxRect32 rect1(MxPoint32(0, 0), MxSize32(p_rect1Width, p_rect1Height));

	MxPoint32 rect2Origin(*p_rect2Left, *p_rect2Top);
	MxRect32 rect2(MxPoint32(0, 0), MxSize32(p_rect2Width, p_rect2Height));

	MxRect32 rect(0, 0, *p_width, *p_height);
	rect.AddPoint(rect1Origin);

	if (!rect.IntersectsWith(rect1)) {
		return FALSE;
	}

	rect.Intersect(rect1);
	rect.SubtractPoint(rect1Origin);
	rect.AddPoint(rect2Origin);

	if (!rect.IntersectsWith(rect2)) {
		return FALSE;
	}

	rect.Intersect(rect2);
	rect.SubtractPoint(rect2Origin);

	*p_rect1Left += rect.GetLeft();
	*p_rect1Top += rect.GetTop();
	*p_rect2Left += rect.GetLeft();
	*p_rect2Top += rect.GetTop();
	*p_width = rect.GetWidth();
	*p_height = rect.GetHeight();
	return TRUE;
}

// FUNCTION: LEGO1 0x100b6ff0
void MakeSourceName(char* p_output, const char* p_input)
{
	const char* cln = strchr(p_input, ':');
	if (cln) {
		p_input = cln + 1;
	}

	strcpy(p_output, p_input);

	strlwr(p_output);

	char* extLoc = strstr(p_output, ".si");
	if (extLoc) {
		*extLoc = 0;
	}
}

// FUNCTION: LEGO1 0x100b7050
MxBool KeyValueStringParse(char* p_outputValue, const char* p_key, const char* p_source)
{
	MxBool didMatch = FALSE;

	MxS16 len = strlen(p_source);
	char* temp = new char[len + 1];
	strcpy(temp, p_source);

	char* token = strtok(temp, ", \t\r\n:");
	while (token) {
		len -= (strlen(token) + 1);

		if (strcmpi(token, p_key) == 0) {
			if (p_outputValue && len > 0) {
				char* cur = &token[strlen(p_key)];
				cur++;
				while (*cur != ',') {
					if (*cur == ' ' || *cur == '\0' || *cur == '\t' || *cur == '\n' || *cur == '\r') {
						break;
					}
					*p_outputValue++ = *cur++;
				}
				*p_outputValue = '\0';
			}

			didMatch = TRUE;
			break;
		}

		token = strtok(NULL, ", \t\r\n:");
	}

	delete[] temp;
	return didMatch;
}

// FUNCTION: LEGO1 0x100b7170
MxBool ContainsPresenter(MxCompositePresenterList& p_presenterList, MxPresenter* p_presenter)
{
	for (MxCompositePresenterList::iterator it = p_presenterList.begin(); it != p_presenterList.end(); it++) {
		if (p_presenter == *it || ((*it)->IsA("MxCompositePresenter") &&
								   ContainsPresenter(((MxCompositePresenter*) *it)->GetList(), p_presenter))) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100b71e0
void OmniError(const char* p_message, MxS32 p_status)
{
	if (g_omniUserMessage) {
		g_omniUserMessage(p_message, p_status);
	}
	else if (p_status) {
		abort();
	}
}

// FUNCTION: LEGO1 0x100b7210
void SetOmniUserMessage(void (*p_omniUserMessage)(const char*, MxS32))
{
	g_omniUserMessage = p_omniUserMessage;
}

// FUNCTION: LEGO1 0x100b7220
void FUN_100b7220(MxDSAction* p_action, MxU32 p_newFlags, MxBool p_setFlags)
{
	p_action->SetFlags(!p_setFlags ? p_action->GetFlags() & ~p_newFlags : p_action->GetFlags() | p_newFlags);

	if (p_action->IsA("MxDSMultiAction")) {
		MxDSActionListCursor cursor(((MxDSMultiAction*) p_action)->GetActionList());
		MxDSAction* action;

		while (cursor.Next(action)) {
			FUN_100b7220(action, p_newFlags, p_setFlags);
		}
	}
}

// Should probably be somewhere else
// FUNCTION: LEGO1 0x100c0280
MxDSObject* CreateStreamObject(MxDSFile* p_file, MxS16 p_ofs)
{
	MxU8* buf;
	_MMCKINFO tmpChunk;

	if (p_file->Seek(((MxLong*) p_file->GetBuffer())[p_ofs], 0)) {
		return NULL;
	}

	if (p_file->Read((MxU8*) &tmpChunk.ckid, 8) == 0 && tmpChunk.ckid == FOURCC('M', 'x', 'S', 't')) {
		if (p_file->Read((MxU8*) &tmpChunk.ckid, 8) == 0 && tmpChunk.ckid == FOURCC('M', 'x', 'O', 'b')) {

			buf = new MxU8[tmpChunk.cksize];
			if (!buf) {
				return NULL;
			}

			if (p_file->Read(buf, tmpChunk.cksize) != 0) {
				return NULL;
			}

			// Save a copy so we can clean up properly, because
			// this function will alter the pointer value.
			MxU8* copy = buf;
			MxDSObject* obj = DeserializeDSObjectDispatch(&buf, -1);
			delete[] copy;
			return obj;
		}
		return NULL;
	}

	return NULL;
}
