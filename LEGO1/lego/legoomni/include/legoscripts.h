#ifndef LEGOSCRIPTS_H
#define LEGOSCRIPTS_H

typedef enum IntroScript {
	IntroScript_Lego_Movie = 0,
	IntroScript_Mindscape_Movie,
	IntroScript_Intro_Movie,
	IntroScript_Outro_Movie,
	IntroScript_BadEnd_Movie,
	IntroScript_GoodEnd_Movie
};

typedef enum InfomainScript {
	InfoMainScript_WelcomeDialogue = 500,
	InfoMainScript_RandomDialogue1 = 502,
	InfoMainScript_LetsGetStarted = 504,
	InfoMainScript_ReturnBack = 514,
	InfoMainScript_ExitConfirmation = 522,
	InfoMainScript_GoodEndingDialogue = 539,
	InfoMainScript_BadEndingDialogue = 540,
	InfoMainScript_PepperCharacterSelect = 541,
	InfoMainScript_MamaCharacterSelect = 542,
	InfoMainScript_PapaCharacterSelect = 543,
	InfoMainScript_OfficierCharacterSelect = 544,
	InfoMainScript_LoraCharacterSelect = 545,
};

typedef enum SndAmimScript {
	SndAmimScript_BookWig = 400
};

#endif // LEGOSCRIPTS_H
