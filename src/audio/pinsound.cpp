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
int PinSound::m_sdl_STD_idx = 0;  // the table sounds
int PinSound::m_sdl_BG_idx  = 0;  //the BG sounds/music

// state of sound device and mixer setup
bool PinSound::isSDLAudioInitialized = false;

// define the audio spec for mono files.  We want all table sounds in mono for 3d
SDL_AudioSpec PinSound::m_audioSpecMono;

// SDL_mixer
int PinSound::m_maxSDLMixerChannels = 200; // max # of chans were allocated to mixer on init
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

      // Display output settings of device
      Mix_QuerySpec(&m_mixEffectsData.outputFrequency, &m_mixEffectsData.outputFormat, &m_mixEffectsData.outputChannels);
      PLOGI << "Output Device Settings: " << "Freq: " << m_mixEffectsData.outputFrequency << " Format (SDL_AudioFormat): " << m_mixEffectsData.outputFormat
      << " channels: " << m_mixEffectsData.outputChannels;
   }     
   // set the MixEffects output params that are used for resampling the incoming stream to callback.
   Mix_QuerySpec(&m_mixEffectsData.outputFrequency, &m_mixEffectsData.outputFormat, &m_mixEffectsData.outputChannels);
   
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
   
      // set the global vpinball.. name should be changed for bass to sdl...
      g_pvp->m_ps.bass_BG_idx = m_sdl_BG_idx; // BG sounds
      g_pvp->m_ps.bass_STD_idx = m_sdl_STD_idx; // table sounds

      SDL_Init(SDL_INIT_AUDIO);
      SDL_AudioDeviceID tableSounds = NULL;
      SDL_AudioDeviceID bgSounds = NULL;

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "Failed to initialize SDL: " << SDL_GetError();
        return;        
      }

      // change the AudioSpec param when we know what sound format out we want.  or get from device
      if (SDL_Init(Mix_OpenAudio(m_sdl_STD_idx,NULL)) < 0) {
        PLOGE << "Failed to initialize SDl_MIXER: " << SDL_GetError();
        return;        
      }

      int chans = Mix_AllocateChannels(m_maxSDLMixerChannels); // set the max channel pool
      PLOGI << "SDL_mixer Allocated " << chans << " channels.";

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

// Loads the WAV files into channels
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
   
   // this is not nedded righ now...  But once 3d sound is active then yes  
   const SoundConfigTypes SoundMode3D = (m_outputTarget == SNDOUT_BACKGLASS) ? SNDCFG_SND3D2CH : (SoundConfigTypes)g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);

   m_psdlIOStream = SDL_IOFromMem(m_pdata, static_cast<int>(m_cdata)); 

   if (!m_psdlIOStream) {
        PLOGE << "SDL_IOFromMem error: " << SDL_GetError();
        return E_FAIL;
    }

   if(! (m_pMixChunk = Mix_LoadWAV_IO(m_psdlIOStream, true)))
   {
      PLOGE << "Failed to load sound: " << SDL_GetError();
      return E_FAIL;
   }

   // assign a channel to sound
   if( (m_assignedChannel = getChannel()) == -1) // no more channels.. increase max
   {
      PLOGE << "There are no more mixer channels avaiable to be allocated.  ??";
      return E_FAIL;
   }

   PLOGI << "Loaded Sound File: " << m_szName << " Assigned Channel: " << m_assignedChannel;
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

// Called to play the table sounds
void PinSound::Play(const float volume, const float randompitch, const int pitch, const float pan, const float front_rear_fade, const int flags, const bool restart)
{
   // setup the struct for the effects processing
    m_mixEffectsData.pitch = pitch;
    m_mixEffectsData.randompitch = randompitch;
    m_mixEffectsData.front_rear_fade = front_rear_fade;

    //PLOGI << "Playing Sound: " << m_szName << " Vol: " << volume << " pan: " << pan << " Pitch: "<< pitch << " Random pitch: " << randompitch <<   " Flags: " << flags << " Restart? " << restart;
   
   // normalize sound to sdl mixer range.  0-128
   float nVolume = 0 + volume * (MIX_MAX_VOLUME - 0);
   
   // calculate pan volumes
   int leftVolume;
   int rightVolume;
   CalculatePanVolumes(leftVolume, rightVolume, pan, nVolume);
  
   if (Mix_Playing(m_assignedChannel)) {
     Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
     if (restart){ // stop and reload
      Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
      Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      // register the pitch effect.  must do this each time before PlayChannel
      Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
     }
   } 
   else { // not playing
      // register the pitch effect.  must do this each time before PlayChannel
      Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
      
      Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }
}

// Called to stop table sounds
void PinSound::Stop() 
{
   Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
}

// Calculate the pan volume for each speaker based on the pintable value sent
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

// Loads a music file .  Used by WMP.
bool PinSound::SetMusicFile(const string& szFileName)
{
   if(m_pMixMusic != nullptr)
       Mix_FreeMusic(m_pMixMusic);
   
   if(!(m_pMixMusic = Mix_LoadMUS(szFileName.c_str())))
   {
      PLOGE << "Failed to load sound: " << SDL_GetError();
      return false;
   }

   PLOGI << "Loaded Music File: " << szFileName;
   return true;
}

// Loads Music file. Used by PlayMusic 
// In the table when it uses 'PlayMusic'. These are typcially in the music folder.  
bool PinSound::MusicInit(const string& szFileName, const float volume)
{
   #ifndef __STANDALONE__
      const string& filename = szFileName;
   #else
      const string filename = normalize_path_separators(szFileName);
   #endif

   if(m_pMixMusic != nullptr)
         Mix_FreeMusic(m_pMixMusic);

   // need to find the path of the music dir. This does hunt to find the file.
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
     
      if ((m_pMixMusic = Mix_LoadMUS(path.c_str())))
      {
         MusicVolume(volume);
         MusicPlay();
         PLOGI << "Loaded Music File: " << szFileName << " to OutputTarget(0=table, 1=BG): " << 
            static_cast<int>(m_outputTarget); 
         return true;
      }
   }
   PLOGE << "Failed to load sound: " << szFileName << " SDL Error: " << SDL_GetError();
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

// Inits the SDL Audio Streaming interface 
// Used by VPinMAMEController and PUP
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

// called by VPinMAMEController and PUP
void PinSound::StreamUpdate(void* buffer, DWORD length) 
{
   SDL_PutAudioStreamData(m_pstream, buffer, length);
}

// called by VPinMAMEController, pup
// pup sends a value between 0 and 1.. matches sdl stream volume scale
void PinSound::StreamVolume(const float volume)
{
   if (m_streamVolume != volume)
   {
      SDL_SetAudioStreamGain(m_pstream, volume);
      m_streamVolume = volume;
   }
}

// Static - adjust pitch function... Called when registered with Mix_RegisterEffect
void PinSound::PitchEffect(int chan, void *stream, int len, void *udata) {
   MixEffectsData* med = static_cast<MixEffectsData*>(udata); 
   if(med->pitch == 0 && med->randompitch == 0) // no need to resample
      return;
   
   float pitchRatio;

   // 0 no random, .5 half speed, 1 double the freq
   if(med->randompitch > 0)
   {
      const float rndh = rand_mt_01();
      const float rndl = rand_mt_01();
      int freq = med->outputFrequency + (med->outputFrequency * med->randompitch * rndh * rndh) - (med->outputFrequency * 
         med->randompitch * rndl * rndl * 0.5f);
      pitchRatio = (freq + med->pitch) / med->outputFrequency;

      //PLOGI << " random freq = " << freq << " pitchRatio: " << pitchRatio;
   }
   else // just the pitch value
   {
      pitchRatio = (med->outputFrequency + med->pitch) / med->outputFrequency;
   }
   
    switch(med->outputFormat)
    {
      case (SDL_AUDIO_S16LE):
         {
                     // Input and output buffer pointers
               int16_t *input_samples = static_cast<int16_t *>(stream);
               int num_input_samples = len / sizeof(int16_t);
         
               // Output buffer
               std::vector<int16_t> output_samples;
               output_samples.reserve(static_cast<size_t>(num_input_samples / pitchRatio));

               float fractional_pos = 0.0f;;

               for (int i = 0; i < num_input_samples - 1; ++i) {
                  fractional_pos += pitchRatio;
                  while (fractional_pos >= 1.0f) {
                        fractional_pos -= 1.0f;

                        // Perform linear interpolation
                        int16_t interpolated_sample = static_cast<int16_t>(input_samples[i] + 
                           fractional_pos * (input_samples[i + 1] - input_samples[i]));
                        //int16_t interpolated_sample = linearInterpolation(input_samples[i], input_samples[i + 1], fractional_pos);
                        output_samples.push_back(interpolated_sample);
                  }
               }

               // Update fractional position
               //data->fractional_pos = fractional_pos;

               // Copy processed output samples back to the stream
               std::memset(stream, 0, len); // Clear the buffer first
               std::memcpy(stream, output_samples.data(), std::min(len, static_cast<int>(output_samples.size() * sizeof(int16_t))));
               break;
               }
      default:
         {
            PLOGE << "Could not identify audio format encoding size. Type: " << med->outputFormat;
            return;
         }
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


