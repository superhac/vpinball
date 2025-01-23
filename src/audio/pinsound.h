// license:GPLv3+

#pragma once

#include "core/Settings.h"
#include <SDL3_mixer/SDL_mixer.h>

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

// this gets passed to all Mix_RegesterEffect callbacks
struct MixEffectsData
{
   // The output device format info.  This is the format of the audio stream that comes in to be resampled (Mix_RegisterEffect). 
   int outputFrequency;
   SDL_AudioFormat outputFormat; 
   int outputChannels;

   // These are the data points provided by vpinball to adjust sample when resampling
   float pitch;
   float randompitch;
   float front_rear_fade;
};

class PinSound 
{
public:

   // SDL3_mixer
   Mix_Chunk * m_pMixChunk = nullptr;
   Mix_Music * m_pMixMusic = nullptr;

   //SDL Audio
   SDL_AudioSpec m_audioSpec; // audio spec format 
   SDL_IOStream *m_psdlIOStream = nullptr; // the audio stream loader
   SDL_AudioStream *m_pstream = nullptr; // Vpipmame streamer
   float m_streamVolume = 0;
  
   // if the Reinitilize comes back good, We should free these in pintable.cpp or were keeping two copies
   // one here and one from pintable.  Once everything is good we only need Mix_Chunk.   S_FIX S_REMOVE
   char *m_pdata = nullptr; // wav data set by caller directly
   int m_cdata; // wav data length set by caller directly
   
    // Sounds filenames and path
   string m_szName; // only filename, no ext
   string m_szPath; // full filename, incl. path

   PinSound() {};
   PinSound(const Settings& settings);
   ~PinSound();
 
   // plays the table sounds.
   void UnInitialize();
   HRESULT ReInitialize();
   void Play(const float volume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart);
   void Stop();

   //Music Playing from AudioPlayer (used by WMPCore, PlayMusic)
   bool SetMusicFile(const string& szFileName);
   void MusicPlay();
   void MusicStop();
   void MusicPause();
   void MusicUnpause();
   void MusicClose();
   bool MusicActive();
   double GetMusicPosition();
   void SetMusicPosition(double seconds);
   void MusicVolume(const float volume);
   bool MusicInit(const string& szFileName, const float volume);  //player.cpp

   // Plays sounds from Vpinmame and PUP.  These are streams
   bool StreamInit(DWORD frequency, int channels, const float volume);
   void StreamUpdate(void* buffer, DWORD length);
   void StreamVolume(const float volume);

   

   // static class methods
   //
   // Retrieves detected audio devices detected by SDL
	static void EnumerateAudioDevices(vector<AudioDevice>& devices);

   ///////////////////////////////////
   // Canidates for removeal _S_REMOVE
   ///////////////////////////////////

   SoundOutTypes m_outputTarget; //Is it table sound device or BG sound device.  

   SoundOutTypes GetOutputTarget() const { return m_outputTarget; } // called by pintable

   // This is called by pintable just before Reinitialize().  Not needed? S_REMOVE
   void SetOutputTarget(SoundOutTypes target) { 
      m_outputTarget = target;
      }

   // directsound stuff?
   void StopCopiedWav(const string& name) {};
   void StopCopiedWavs() {};
   void StopAndClearCopiedWavs() {};
   void InitPinDirectSound(const Settings& settings, const HWND hwn) {};
   void ReInitPinDirectSound(const Settings& settings, const HWND hwn) {};

   // old wav code only, but also used to convert raw wavs back to BASS
   WAVEFORMATEX m_wfx;
   int m_cdata_org;
   char *m_pdata_org; // save wavs in original raw format

   // not sure remove?
   int m_volume;
   int m_balance;
   int m_fade;
   int bass_BG_idx;
   int bass_STD_idx;


   // See how to get rid of this. called from pintable.cpp  S_REMOVE
   bool IsWav2() const;
   bool IsWav() const; 
   /////////////
   // END REMOVE
   /////////////

private:	

   static bool isSDLAudioInitialized; // tracks the state of one time setup of sounds devices and mixer
   static Settings m_settings; // get key/value from VPinball.ini
   static int m_sdl_STD_idx;  // the table sound device to play sounds out of
	static int m_sdl_BG_idx;  //the BG sounds/music device to play sounds out of
   MixEffectsData m_mixEffectsData;
   
   // we want the table sounds to all be in mono format.  Some are not.  This is used to convert them
   static SDL_AudioSpec m_audioSpecMono;
  
   // SDL_mixer
   int m_assignedChannel;
   static int m_maxSDLMixerChannels; // max channels allocated on init
   static int m_nextAvailableChannel; // channel pool for assignment

   void CalculatePanVolumes(int& leftVolume, int& rightVolume, const float &pan, float baseVolume);

   // Static class methods
   //
   static void initSDLAudio();
   static int getChannel(); // get a channel assigned for the wav
   // Mixer effects (Mix_RegisterEffect)
   void static PitchEffect(int chan, void *stream, int len, void *udata);
};
