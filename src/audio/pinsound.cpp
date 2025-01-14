// license:GPLv3+

/* Notes called by: parts/pintable.cpp
*/

#ifndef pinsound_H // Include guard
#define pinsound_H
#endif
#include "core/stdafx.h"
#include <SDL3_mixer/SDL_mixer.h>
#include <SDL3/SDL.h>

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
      UnInitialize();
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

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "Failed to initialize SDL: " << SDL_GetError() << std::endl;
        return;        
      }

      if (!(tableSounds = SDL_OpenAudioDevice(m_sdl_STD_idx, NULL))) // sound device
         PLOGE << "SDL could not open sound device";
      else
         PLOGI << "SDL successfully opened sound device: " << m_sdl_STD_idx;
         
      if (m_sdl_STD_idx != m_sdl_BG_idx) // inits the second device (BG stereo sound) for for 3d mode. called directsound below?
      { 
         if (!(tableSounds = SDL_OpenAudioDevice(m_sdl_BG_idx, NULL))) // sound BG device
            PLOGE << "SDL could not open BG sound device";
         else 
            PLOGI << "SDL successfully opened BG sound device: " << m_sdl_BG_idx;            
      }
}

 void PinSound::UnInitialize()
 {
   SDL_DestroyAudioStream(m_stream);
   SDL_free(m_audioBuffer);
   SDL_CloseIO(m_sdlIOStream);
   
 }

// CHANGE should really be called loadSound S_COMMENT
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
   m_outputTarget = SNDOUT_TABLE; // may have to set this somewhere else? S_WATCH
   PLOGI << "Loading Sound File: " << m_szName << " to OutputTarget(0=table, 1=BG): " << static_cast<int>(m_outputTarget);
   
   m_sdlIOStream = SDL_IOFromMem(m_pdata, static_cast<int>(m_cdata)); 

   if (!m_sdlIOStream) {
        PLOGE << "SDL_IOFromMem error: " << SDL_GetError();
        return E_FAIL;
    }

    if (!SDL_LoadWAV_IO(m_sdlIOStream, false, &m_audioSpec, &m_audioBuffer, &m_audioLength)) {
        PLOGE << "SDL_LoadWAV_IO error: " << SDL_GetError();
        SDL_CloseIO(m_sdlIOStream);
        return E_FAIL;
    }

    m_stream = SDL_OpenAudioDeviceStream(m_sdl_STD_idx, &m_audioSpec, NULL, NULL);
    if (!m_stream) {
        PLOGE << "SDL_OpenAudioDeviceStream error:  " << SDL_GetError();
        return E_FAIL;
    } 

    // by default the stream is paused.  Must unpause it to use.  ** Always appears to return false even though its successful
    SDL_ResumeAudioStreamDevice(m_stream); 
    
    // Remove this is for testing. S_REMOVE
    // this actually plays the sound!
    //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
    //SDL_Delay(5000);
      
	return S_OK;
}

 bool  PinSound::IsWav() const
   {
      PLOGI << "Called";
      const size_t pos = m_szPath.find_last_of('.');
      if(pos == string::npos)
         return true;
      return StrCompareNoCase(m_szPath.substr(pos+1), "wav"s);
   }

void PinSound::Stop() 
{
    PLOGI << "Called";

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


