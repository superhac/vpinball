// license:GPLv3+

#pragma once

#include "core/Settings.h"
#ifdef __STANDALONE__
#include "SDL3_mixer/SDL_mixer.h"
#endif

enum SoundOutTypes : char { SNDOUT_TABLE = 0, SNDOUT_BACKGLASS = 1 };
enum SoundConfigTypes : int { SNDCFG_SND3D2CH = 0, SNDCFG_SND3DALLREAR = 1, SNDCFG_SND3DFRONTISREAR = 2, 
                              SNDCFG_SND3DFRONTISFRONT = 3, SNDCFG_SND3D6CH = 4, SNDCFG_SND3DSSF = 5};

// Surround modes
// ==============
//
// 2CH:  Standard stereo output
//
// ALLREAR: All table effects shifted to rear channels.   This can replace the need to use two sound cards to move table audio
// inside the cab.  Default backglass audio and VPinMame audio plays from front speakers.
//
// FRONTISFRONT: Recommended mapping for a dedicated sound card attached to the playfield.   Front channel maps to the front
// of the cab.   We "flip" the rear to the standard 2 channels, so older versions of VP still play sounds on the front most
// channels of the cab.    This mapping could also be used to place 6 channels on the playfield. 
//
// FRONTISREAR: Table effects are mapped such that the front of the cab is the rear surround channels.   If you were to play
// VPX in a home theater system with the TV in front of you, this would produce an appropriate result with the ball coming 
// from the rear channels as it get closer to you.  
//
// 6CH: Rear of playfield shifted to the sides, and front of playfield shifted to the far rear.   Leaves front channels open
// for default backglass and VPinMame. 
//
// SSF: 6CH still doesn't map sounds for SSF as distinctly as it could.. In this mode horizontal panning and vertical fading 
// are enhanced for a more realistic experience.

// sdl enumerated sound device info struct
struct AudioDevice
{
	int id;
	const char name[100];
	unsigned int channels; //number of speakers in this case
};

class PinSound 
{
public:
   PinSound(const Settings& settings);
   ~PinSound();
   class PinDirectSound *GetPinDirectSound();
   void SetOutputTarget(SoundOutTypes target) {if (m_outputTarget != target) { m_outputTarget = target; ReInitialize(); } }
   SoundOutTypes GetOutputTarget() const { return m_outputTarget; }
   void UnInitialize();
   HRESULT ReInitialize();
   void SetBassDevice(); //!! BASS only // FIXME move loading code to PinSound and make private
   void Play(const float volume, const float randompitch, const int pitch, const float pan, const float front_rear_fade, const int flags, const bool restart);
   void Stop();

   // remove these.... 
   bool IsWav2() const { return IsWav(); }
   bool IsWav() const; 
   // old wav code only, but also used to convert raw wavs back to BASS
   WAVEFORMATEX m_wfx;
   int m_cdata_org;
   char *m_pdata_org; // save wavs in original raw format

   // not sure remove?
   int m_volume;
   int m_balance;
   int m_fade;
   
   // Sounds filenames and path
   string m_szName; // only filename, no ext
   string m_szPath; // full filename, incl. path

	// GOOD
	SDL_IOStream *m_sdlIOStream = nullptr; // the audio stream
   SDL_AudioStream *m_stream = nullptr; // the stream that actually plays the audio
   Uint8 *m_audioBuffer = nullptr; // audio buffer
   Uint32 m_audioLength = 0; // audio buffer length
   SDL_AudioSpec m_audioSpec; // audio spec format 
   char *m_pdata; // wav data set by caller directly
   int m_cdata; // wav data length set by caller directly
   SoundOutTypes m_outputTarget; //Is it table sound device or BG sound device?

	// static class methods
	static void EnumerateAudioDevices(vector<AudioDevice>& devices);

private:	

   // Good
   static bool isSDL_MixerInitialized; // tracks the state of one time setup of sounds devices and mixer
   static Settings m_settings; // get key/value from VPinball.ini
   static int m_sdl_STD_idx;  // the table sound device to play sounds out of
	static int m_sdl_BG_idx;  //the BG sounds/music device to play sounds out of

   // Methods
	static void initSDL_Mixer();
   
};
