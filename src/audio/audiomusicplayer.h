#pragma once


#include "core/Settings.h"
#include "SDL3_mixer/SDL_mixer.h"



class AudioMusicPlayer
{
public:

    // once BASS is gone remove next line BASS_REMOVE
   int bass_STD_idx = -2, bass_BG_idx = -2;

	AudioMusicPlayer();
	~AudioMusicPlayer();
	
	void InitPinDirectSound(const Settings& settings, const HWND hwn);
    void ReInitPinDirectSound(const Settings& settings, const HWND hwn);
	void StopCopiedWav(const string& name);
    void StopCopiedWavs();
    void StopAndClearCopiedWavs();
    HRESULT PlaySound(BSTR, int, float, float, float, int, VARIANT_BOOL, VARIANT_BOOL, float);
    void Play(PinSound * const pps, const float volume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart);
private:
	
};
