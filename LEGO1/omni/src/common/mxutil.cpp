#include "mxutil.h"

#include "mxdsaction.h"
#include "mxdsactionlist.h"
#include "mxdsfile.h"
#include "mxdsmultiaction.h"
#include "mxdsobject.h"
#include "mxrect32.h"

// GLOBAL: LEGO1 0x101020e8
void (*g_omniUserMessage)(const char*, int);

// FUNCTION: LEGO1 0x100b6e10
MxBool FUN_100b6e10(
	MxS32 p_bitmapWidth,
	MxS32 p_bitmapHeight,
	MxS32 p_videoParamWidth,
	MxS32 p_videoParamHeight,
	MxS32* p_left,
	MxS32* p_top,
	MxS32* p_right,
	MxS32* p_bottom,
	MxS32* p_width,
	MxS32* p_height
)
{
	MxPoint32 topLeft(*p_left, *p_top);
	MxRect32 bitmapRect(MxPoint32(0, 0), MxSize32(p_bitmapWidth, p_bitmapHeight));

	MxPoint32 bottomRight(*p_right, *p_bottom);
	MxRect32 videoParamRect(MxPoint32(0, 0), MxSize32(p_videoParamWidth, p_videoParamHeight));

	MxRect32 rect(0, 0, *p_width, *p_height);
	rect.AddPoint(topLeft);

	if (!rect.IntersectsWith(bitmapRect))
		return FALSE;

	rect.Intersect(bitmapRect);
	rect.SubtractPoint(topLeft);
	rect.AddPoint(bottomRight);

	if (!rect.IntersectsWith(videoParamRect))
		return FALSE;

	rect.Intersect(videoParamRect);
	rect.SubtractPoint(bottomRight);

	*p_left += rect.GetLeft();
	*p_top += rect.GetTop();
	*p_right += rect.GetLeft();
	*p_bottom += rect.GetTop();
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
					if (*cur == ' ' || *cur == '\0' || *cur == '\t' || *cur == '\n' || *cur == '\r')
						break;
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

// FUNCTION: LEGO1 0x100b7210
void SetOmniUserMessage(void (*p_userMsg)(const char*, int))
{
	g_omniUserMessage = p_userMsg;
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
