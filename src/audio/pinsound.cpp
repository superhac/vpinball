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

      // set up the mono audio spec.. freq is set when converting the sound with the orginal freq
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
      if(m_pMixChunk != nullptr)
         SDL_free(m_pMixChunk);
      if(m_pMixMusic != nullptr)
         Mix_FreeMusic(m_pMixMusic);
}

//static - Setup up the sound device(s) and the mixer for each. Runs ones at the class level.
void PinSound::initSDLAudio() 
{
      const int m_sdl_STD_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      const int m_sdl_BG_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
   
      // set the global vpinball.. name should be changed...
      g_pvp->m_ps.bass_BG_idx = m_sdl_BG_idx;
      g_pvp->m_ps.bass_STD_idx = m_sdl_STD_idx;

      SDL_Init(SDL_INIT_AUDIO);
      SDL_AudioDeviceID tableSounds = NULL;
      SDL_AudioDeviceID bgSounds = NULL;

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "Failed to initialize SDL: " << SDL_GetError() << std::endl;
        return;        
      }

      // change the AudioSpec param when we know what sound format out we want.  or get from device
      if (SDL_Init(Mix_OpenAudio(m_sdl_STD_idx,NULL)) < 0) {
        PLOGE << "Failed to initialize SDl_MIXER: " << SDL_GetError() << std::endl;
        return;        
      }

      int chans = Mix_AllocateChannels(m_maxSDLMixerChannels); // set the max channel pool
      PLOGI << "SDL_mixer Allocated " << chans<< " channels.";

      int frequency;
      SDL_AudioFormat format; 
      int channels;
      Mix_QuerySpec(&frequency, &format, &channels);
      PLOGI << "Output Device Settings: " << "Freq: " << frequency << " Format: " << format << " channels: " << channels;

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
   
 }

// CHANGE should really be called loadSound S_COMMENT
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
   
   // this may not be needed. Or at least righ now... S_REMOVE
   const SoundConfigTypes SoundMode3D = (m_outputTarget == SNDOUT_BACKGLASS) ? SNDCFG_SND3D2CH : (SoundConfigTypes)g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);

   m_psdlIOStream = SDL_IOFromMem(m_pdata, static_cast<int>(m_cdata)); 

   if (!m_psdlIOStream) {
        PLOGE << "SDL_IOFromMem error: " << SDL_GetError();
        return E_FAIL;
    }

   m_pMixChunk = Mix_LoadWAV_IO(m_psdlIOStream, true); 

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
   SDL_Delay(3000); */
   //return E_FAIL;

   PLOGI << "Loaded Sound File: " << m_szName << " to OutputTarget(0=table, 1=BG): " << 
     static_cast<int>(m_outputTarget) << " Assigned Channel: " << m_assignedChannel;

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
    //PLOGI << "Playing Sound: " << m_szName << " Vol: " << volume << " pan: " << pan << " Pitch: "<< pitch << " Flags: " << flags << " Restart? " << restart;
   
   // normalize sound to sdl mixer range.  0-128
   float nVolume = clamp( (((volume - 0) / (100 - 0)) * (MIX_MAX_VOLUME - 0) + 0), 0, MIX_MAX_VOLUME);
   int leftVolume;
   int rightVolume;
   CalculatePanVolumes(leftVolume, rightVolume, pan, nVolume);
  

   if (Mix_Playing(m_assignedChannel)) {
     Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
     if (restart){ // stop and reload
      Stop();
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
     }
   } 
   else { // not playing
      Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }
}

void PinSound::Stop() 
{
   Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
}

void PinSound::CalculatePanVolumes(int& leftVolume, int& rightVolume, float pan, float baseVolume)
{
    pan = max(-10.0f, std::min(10.0f, pan));

    // Normalize pan to the range [-1.0, 1.0]
    float normalizedPan = pan / 10.0f;

    // Calculate left and right volumes based on the pan position
    leftVolume = static_cast<int>(baseVolume * (1.0f - std::max(0.0f, normalizedPan)));
    rightVolume = static_cast<int>(baseVolume * (1.0f + std::min(0.0f, normalizedPan)));

    // Ensure volume levels stay within range
    leftVolume = clamp(leftVolume, 0, baseVolume);
    rightVolume = clamp(rightVolume, 0, baseVolume);
}

bool PinSound::SetMusicFile(const string& szFileName)
{
   if(m_pMixMusic != nullptr)
       Mix_FreeMusic(m_pMixMusic);
   m_pMixMusic = Mix_LoadMUS(szFileName.c_str());

   if(!m_pMixMusic)
   {
   
      if(m_showFileNotFoundError)
         PLOGE << "Failed to load sound: " << SDL_GetError();
      return false;
   }

   PLOGI << "Loaded WMP Music File: " << szFileName << " to OutputTarget(0=table, 1=BG): " << 
     static_cast<int>(m_outputTarget); //<< " Assigned Channel: " << m_assignedChannel;

   return true;
}

// In the table when it uses 'PlayMusic'. These are typcially in the music folder.  
//Found Fleetwood table uses this.
bool PinSound::MusicInit(const string& szFileName, const float volume)
{

   #ifndef __STANDALONE__
      const string& filename = szFileName;
   #else
      const string filename = normalize_path_separators(szFileName);
   #endif

   //turn off failed loading message when we are searching paths for music files
   m_showFileNotFoundError = false;

   // need to find the path of the music dir.
   for (int i = 0; i < 5; ++i)
   {
      string path;
      switch (i)
      {
      case 0: path = filename; break;
      case 1: path = g_pvp->m_szMyPath + "music" + PATH_SEPARATOR_CHAR + filename; break;
      case 2: path = g_pvp->m_currentTablePath + filename; break;
      case 3: path = g_pvp->m_currentTablePath + "music" + PATH_SEPARATOR_CHAR + filename; break;
      case 4: path = PATH_MUSIC + filename; break;
      }
      if (SetMusicFile(path))
      {
         m_showFileNotFoundError = true; // turn it back on.
         MusicVolume(volume);
         MusicPlay();
         return true;
      }
        
   }
    return false;
}

void PinSound::MusicPlay()
{
   Mix_PlayMusic(m_pMixMusic, 0);
}

void PinSound::MusicPause()
{
   Mix_PauseMusic();
}

void PinSound::MusicUnpause()
{
   Mix_ResumeMusic();
}

void PinSound::MusicClose()
{
   MusicStop(); 
}

bool PinSound::MusicActive() {
   return Mix_PlayingMusic();
}

void PinSound::MusicStop()
{
   Mix_HaltMusic();
}

double PinSound::GetMusicPosition()
{
   return Mix_GetMusicPosition(m_pMixMusic);
}

void PinSound::SetMusicPosition(double seconds)
{
   Mix_SetMusicPosition(seconds);
}

void PinSound::MusicVolume(const float volume)
{
   int nVolume=volume*(MIX_MAX_VOLUME-0)+0;
   Mix_VolumeMusic(nVolume);
}

// called from VPinMAMEController
bool PinSound::StreamInit(DWORD frequency, int channels, const float volume) 
{
   PLOGI << "Stream Init";
   SDL_AudioSpec audioSpec;
   audioSpec.freq = frequency;
   audioSpec.format =  SDL_AUDIO_S16LE;
   audioSpec.channels = channels;

   m_pstream = SDL_OpenAudioDeviceStream(g_pvp->m_ps.bass_BG_idx, &audioSpec, NULL, NULL);
   if(m_pstream)
   {
      SDL_ResumeAudioStreamDevice(m_pstream); // it always stops paused
      return true;
   }
   return false;  
}

// called from VPinMAMEController
void PinSound::StreamUpdate(void* buffer, DWORD length) 
{
   SDL_PutAudioStreamData(m_pstream, buffer, length);
}

//called from VPinMAMEController, pup
// pup sends a value between 0 and 1
void PinSound::StreamVolume(const float volume)
{
   if (m_streamVolume != volume)
   {
      SDL_SetAudioStreamGain(m_pstream, volume);
      m_streamVolume = volume;
   }
}

// Static - get an avialble channel assigned
int PinSound::getChannel()
{
   if(m_nextAvailableChannel == m_maxSDLMixerChannels) // we're out of channels. increase by 100
      {
         m_maxSDLMixerChannels = Mix_AllocateChannels(m_maxSDLMixerChannels + 100);
         PLOGI << "Allocated another 100 mixer channels.  Total Avail: " <<  m_maxSDLMixerChannels;
      }
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


