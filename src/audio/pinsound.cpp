// license:GPLv3+

/* Notes called by: parts/pintable.cpp
*/

#ifndef pinsound_H // Include guard
#define pinsound_H
#endif
#include "core/stdafx.h"
#include <SDL3_mixer/SDL_mixer.h>
#include <SDL2/SDL.h>

// Retrieve settings from the VPinball.ini file
Settings PinSound::m_settings = nullptr;

// SDL Sound Device Id for each output 
int PinSound::m_sdl_STD_idx =0;  // the table sounds
int PinSound::m_sdl_BG_idx = 0;  //the BG sounds/music

// state of sound device and mixer setup
bool PinSound::isSDL_MixerInitialized = false;

PinSound::PinSound(const Settings& settings)
{
   if (!isSDL_MixerInitialized) {
      m_settings = settings;
      PinSound::initSDL_Mixer();
      isSDL_MixerInitialized = true;
   }
   // debug REMOVE
   //else
      //PLOGI << "PinSound Already initialized";        
}

PinSound::~PinSound()
{
      
}

//static - Setup up the sound device(s) and the mixer for each. Runs ones at the class level.
void PinSound::initSDL_Mixer() 
{
      const int DSidx1 = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      const int DSidx2 = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
   
      SDL_Init(SDL_INIT_AUDIO);
      SDL_AudioDeviceID tableSounds = NULL;
      SDL_AudioDeviceID bgSounds = NULL;
      m_sdl_STD_idx = DSidx1; // table 3d sounds
      m_sdl_BG_idx = DSidx2; // BG music

      if (!(tableSounds = SDL_OpenAudioDevice(m_sdl_STD_idx, NULL))) // sound device
         PLOGE << "SDL could not open sound device";
      else {
         PLOGI << "SDL successfully opened sound device: " << m_sdl_STD_idx;
         if( !Mix_OpenAudio( tableSounds, nullptr ) )
         PLOGE << "SDL_mixer could not bw started";
         else
            PLOGI << "SDL_mixer successfully started on sound device: " << m_sdl_STD_idx;
      }
      if (m_sdl_STD_idx != m_sdl_BG_idx) // inits the second device (BG stereo sound) for for 3d mode. called directsound below?
      { 
         if (!(tableSounds = SDL_OpenAudioDevice(m_sdl_BG_idx, NULL))) // sound BG device
            PLOGE << "SDL could not open BG sound device";
         else {
            PLOGI << "SDL successfully opened BG sound device: " << m_sdl_BG_idx;
            if( !Mix_OpenAudio( tableSounds, nullptr ) )
               PLOGE << "SDL_mixer could not bw started";
            else
               PLOGI << "SDL_mixer successfully started on sound device: " << m_sdl_BG_idx;
         }
      }
}

 void PinSound::UnInitialize()
 {

 }

HRESULT PinSound::ReInitialize() {
	UnInitialize();
   PLOGI << "Called1: " << m_szPath;
	// loads up all the music/sound files into memory

	//return S_OK;
	return E_FAIL;

}

 bool  PinSound::IsWav() const
   {
      const size_t pos = m_szPath.find_last_of('.');
      if(pos == string::npos)
         return true;
      return StrCompareNoCase(m_szPath.substr(pos+1), "wav"s);
   }

void PinSound::Stop() 
{

}
//Static - Returns a vector of audio devices found 
void PinSound::EnumerateAudioDevices(vector<AudioDevice>& audioDevices)
{
   SDL_Init(SDL_INIT_AUDIO);
   audioDevices.clear();
   int count;
   SDL_AudioDeviceID * audioList = SDL_GetAudioPlaybackDevices(&count);
   
   for (int i = 0; i < count; ++i) {
	AudioDevice audioDevice = {}; 
	audioDevice.id = audioList[i];
	strcpy((char*)audioDevice.name, SDL_GetAudioDeviceName(audioList[i]));
	SDL_AudioSpec spec;
	SDL_GetAudioDeviceFormat( audioList[i], &spec, NULL);
	audioDevice.channels = spec.channels;
	SDL_CloseAudioDevice(audioList[i]);
	audioDevices.push_back(audioDevice);
	}
	SDL_Quit();
}


