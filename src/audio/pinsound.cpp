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
bool PinSound::isSDLAudioInitialized = false;

// define the audio spec for mono files.  We want all table sounds in mono for 3d
 SDL_AudioSpec PinSound::m_audioSpecMono;

// SDL_mixer
int PinSound::m_maxSDLMixerChannels = 200; // max # of chans were allocated to mixer
int PinSound::m_nextAvailableChannel = 0; // new sound, gets new chan

PinSound::PinSound(const Settings& settings)
{
   if (!isSDLAudioInitialized) {

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "SDL Init failed: " << SDL_GetError();
        return;
      }

      m_settings = settings;

      // set up the mono audio spec
      PinSound::m_audioSpecMono.channels = 1;
      PinSound::m_audioSpecMono.format = SDL_AUDIO_S16LE;

      PinSound::initSDLAudio();
      isSDLAudioInitialized = true;
   }     
}

PinSound::~PinSound()
{
      UnInitialize();
      delete [] m_pdata;
}

//static - Setup up the sound device(s) and the mixer for each. Runs ones at the class level.
void PinSound::initSDLAudio() 
{
      const int m_sdl_STD_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      const int m_sdl_BG_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
   
      SDL_Init(SDL_INIT_AUDIO);
      SDL_AudioDeviceID tableSounds = NULL;
      SDL_AudioDeviceID bgSounds = NULL;
      //m_sdl_STD_idx = DSidx1; // table 3d sounds
      //m_sdl_BG_idx = DSidx2; // BG music

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "Failed to initialize SDL: " << SDL_GetError() << std::endl;
        return;        
      }

      // change the AudioSpec param when we know what sound format out we want.  or get from device
      if (SDL_Init(Mix_OpenAudio(m_sdl_STD_idx,NULL)) < 0) {
        PLOGE << "Failed to initialize SDl_MIXER: " << SDL_GetError() << std::endl;
        return;        
      }

      int chans = Mix_AllocateChannels(m_maxSDLMixerChannels);
      PLOGI << "SDL_mixer Allocated " << chans<< " channels.";

      // once two sound devices are supported add this back in. change to mixer..    
 /*      if (m_sdl_STD_idx != m_sdl_BG_idx) // inits the second device (BG stereo sound) for for 3d mode. called directsound below?
      { 
         if (!(tableSounds = SDL_OpenAudioDevice(m_sdl_BG_idx, NULL))) // sound BG device
            PLOGE << "SDL could not open BG sound device";
         else 
            PLOGI << "SDL successfully opened BG sound device: " << m_sdl_BG_idx;            
      } */
}

 void PinSound::UnInitialize()
 {
   SDL_DestroyAudioStream(m_stream);
   SDL_free(m_audioBuffer);
   SDL_CloseIO(m_sdlIOStream);
   //delete [] m_pdata;
   
 }

// CHANGE should really be called loadSound S_COMMENT
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
  
  //return E_FAIL;

   PLOGI << "Loading Sound File: " << m_szName << " to OutputTarget(0=table, 1=BG): " << static_cast<int>(m_outputTarget);

   // this may not be needed. Or at least righ now... S_REMOVE
   const SoundConfigTypes SoundMode3D = (m_outputTarget == SNDOUT_BACKGLASS) ? SNDCFG_SND3D2CH : (SoundConfigTypes)g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);


   m_sdlIOStream = SDL_IOFromMem(m_pdata, static_cast<int>(m_cdata)); 

   if (!m_sdlIOStream) {
        PLOGE << "SDL_IOFromMem error: " << SDL_GetError();
        return E_FAIL;
    }

   m_pMixChunk = Mix_LoadWAV_IO( m_sdlIOStream, false); // this can't be set to true or it seg faults?  sdk claims it can be closed?

   if(!m_pMixChunk)
   {
      PLOGE << "Failed to load sound: " << SDL_GetError();
      return E_FAIL;
   }

   //assign a channel to sound
   if( (m_assignedChannel = getChannel()) == -1) // no more channels.. increase max
   {
      PLOGE << "There are no more mixer channels avaiable to be allocated.  Increase m_maxSDLMixerChannels";
      return E_FAIL;
   }


   // testingdd
   /* PLOGI << "Sound Assinged to Channel: " << m_assignedChannel;
   Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   // Wait a few seconds to hear the sound
   SDL_Delay(3000); */
   //return E_FAIL;

	return S_OK;
}
 // See how to get rid of this. called from pintable.cpp  S_REMOVE
 bool PinSound::IsWav() const { 
   PLOGI << "Called";
   return false; }

 // See how to get rid of this. called from pintable.cpp S_REMOVE
 bool  PinSound::IsWav2() const
   {
      //PLOGI << "Called";
      const size_t pos = m_szPath.find_last_of('.');
      if(pos == string::npos)
         return true;
      return StrCompareNoCase(m_szPath.substr(pos+1), "wav"s);
   }

void PinSound::Play(const float volume, const float randompitch, const int pitch, const float pan, const float front_rear_fade, const int flags, const bool restart)
{

   PLOGI << "Playing Sound: " << m_szName << " Vol: " << volume << " Flags: " << flags << " Restart? " << restart;
   float nVolume = ((volume - 0) / (100 - 0)) * (MIX_MAX_VOLUME - 0) + 0;
   PLOGI << "Volume: " << volume << " New volume: " << nVolume;

   if (Mix_Playing(m_assignedChannel)) {
    // Data is available in the stream
     PLOGI << "Data still in stream...";
     Mix_Volume(m_assignedChannel, nVolume);

     if (restart){ // stop and reload
       PLOGI << "Stopping and restarting stream";
      //AdjustVolume(volume, true);
      Stop();
      //AdjustVolume(volume, false);
      //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
      //SDL_ResumeAudioStreamDevice(m_stream); 
     }
   } 
   else { // not playing
      
      
      //Mix_Volume(m_assignedChannel, nVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      //AdjustVolume(volume, false);
      //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
      //SDL_ResumeAudioStreamDevice(m_stream); 
   }
}

void PinSound::Stop() 
{
   Mix_HaltChannel(m_assignedChannel);
    //PLOGI << "Called";
    //SDL_PauseAudioStreamDevice(m_stream);
    //SDL_ClearAudioStream(m_stream);

}

// Static - get an aviable channel assigned
int PinSound::getChannel()
{
   if(m_nextAvailableChannel == m_maxSDLMixerChannels) // were out of channels. increase max
      return -1;
   return m_nextAvailableChannel++;
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


