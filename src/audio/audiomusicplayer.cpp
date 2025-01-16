#include "core/stdafx.h"
#ifndef audiomusicplayer_H // Include guard
#define audiomusicplayer_H
#endif
#ifndef pinsound_H // Include guard
#define pinsound_H
#endif


AudioMusicPlayer::AudioMusicPlayer()
{

}

AudioMusicPlayer::~AudioMusicPlayer()
{

}


// called from vpinball.cpp @ 1846
// const HWND hwn doesnt appear to be used?  A windows window handler?
void AudioMusicPlayer::InitPinDirectSound(const Settings& settings, const HWND hwn)
{
    PLOGI << "Called";
    // gives us the settings from VPinball.ini.. Like SoundDevice, SoundDeviceBG, etc
   const int DSidx1 = settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
   const int DSidx2 = settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
   const SoundConfigTypes SoundMode3D = (SoundConfigTypes)settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);

   //g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);
}

void AudioMusicPlayer::ReInitPinDirectSound(const Settings& settings, const HWND hwn)
{
     //PLOGI << "Called";
    /* if (m_pbackglassds != &m_pds) delete m_pbackglassds;
      BASS_Stop();
      BASS_Free();

		InitPinDirectSound(settings, hwnd); */

    //g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);

}

void AudioMusicPlayer::StopCopiedWav(const string& name) 
{
    // this had windows only code
    // DirectSoundBuffer code 
}

void AudioMusicPlayer::StopCopiedWavs()
{
    // windows only directsound stuff
}

void AudioMusicPlayer::StopAndClearCopiedWavs() 
{
    // move windows directsound stuff.. works with this pDSBuffer
}

HRESULT AudioMusicPlayer::PlaySound(BSTR, int, float, float, float, int, VARIANT_BOOL, VARIANT_BOOL, float)
{
    PLOGI << "Called";
    //return S_OK;
	return E_FAIL;
}

void AudioMusicPlayer::Play(PinSound * const pps, const float volume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
               {
                 PLOGI << "Playing: " << pps->m_szName;
                 pps->Play(volume, randompitch, pitch, pan, front_rear_fade, NULL, restart); // find out what flags are?  S_COMMENT

               }