#include "legoloopinganimpresenter.h"

#include "anim/legoanim.h"
#include "legocameracontroller.h"
#include "legoworld.h"
#include "mxcompositepresenter.h"
#include "mxdsaction.h"
#include "mxdssubscriber.h"

DECOMP_SIZE_ASSERT(LegoLoopingAnimPresenter, 0xc0)

// FUNCTION: LEGO1 0x1006caa0
// FUNCTION: BETA10 0x1005223d
void LegoLoopingAnimPresenter::StreamingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_unk0x95) {
		ProgressTickleState(e_done);
		if (m_compositePresenter) {
			if (m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				m_compositePresenter->VTable0x60(this);
			}
		}
	}
	else {
		if (m_action->GetDuration() != -1) {
			if (m_action->GetElapsedTime() > m_action->GetDuration() + m_action->GetStartTime()) {
				m_unk0x95 = TRUE;
			}
		}
	}
}

// FUNCTION: LEGO1 0x1006cb40
// FUNCTION: BETA10 0x1005239a
void LegoLoopingAnimPresenter::PutFrame()
{
	MxLong time;

	if (m_action->GetStartTime() <= m_action->GetElapsedTime()) {
		time = (m_action->GetElapsedTime() - m_action->GetStartTime()) % m_anim->GetDuration();
	}
	else {
		time = 0;
	}

	FUN_1006b9a0(m_anim, time, m_unk0x78);

	if (m_unk0x8c != NULL && m_currentWorld != NULL && m_currentWorld->GetCamera() != NULL) {
		for (MxS32 i = 0; i < m_unk0x94; i++) {
			if (m_unk0x8c[i] != NULL) {
				MxMatrix mat(m_unk0x8c[i]->GetLocal2World());

				Vector3 pos(mat[0]);
				Vector3 dir(mat[1]);
				Vector3 up(mat[2]);
				Vector3 und(mat[3]);

				float possqr = sqrt(pos.LenSquared());
				float dirsqr = sqrt(dir.LenSquared());
				float upsqr = sqrt(up.LenSquared());

				up = und;

				up -= m_currentWorld->GetCamera()->GetWorldLocation();
				dir /= dirsqr;
				pos.EqualsCross(&dir, &up);
				pos.Unitize();
				up.EqualsCross(&pos, &dir);
				pos *= possqr;
				dir *= dirsqr;
				up *= upsqr;

				m_unk0x8c[i]->FUN_100a58f0(mat);
				m_unk0x8c[i]->VTable0x14();
			}
		}
	}
}
