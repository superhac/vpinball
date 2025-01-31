// license:GPLv3+

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

// holds the setting from VPinball.ini that says what SoundMode were in.
SoundConfigTypes PinSound::m_SoundMode3D;

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

      // Set the output AudioSpec and display output settings of device
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
      //delete [] m_pdata;
}

//static - Setup up the sound device(s) and the mixer for each. Runs ones at the class level.
void PinSound::initSDLAudio() 
{
      const int m_sdl_STD_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      const int m_sdl_BG_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      PinSound::m_SoundMode3D = (SoundConfigTypes) m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (SoundConfigTypes)SNDCFG_SND3D2CH);

   
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
      if(m_pMixChunk != nullptr)
      {
         Mix_FreeChunk(m_pMixChunk);
         m_pMixChunk = nullptr;
      }
      if(m_pMixMusic != nullptr) 
      {
         Mix_FreeMusic(m_pMixMusic);
         m_pMixMusic = nullptr;
      }

      if (m_pstream) 
      {
         SDL_DestroyAudioStream(m_pstream);
         m_pstream = nullptr;
      }
 }

// Loads the WAV files into channels
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
  
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

   PLOGI << "Loaded Sound File: " << m_szName << " Sound Type: " << getFileExt() << 
      " # of Audio Channels: " << ( (getFileExt() =="wav") ? std::to_string(getChannelCountWav() ) : "Unknown" ) <<
      " Assigned Channel: " << m_assignedChannel << " SoundOut (0=table, 1=bg): " << (int)m_outputTarget;

	return S_OK;
}

// These are BG sounds that are loaded in the table.  They show up in the windows versions Sound Manger.
// But instead of being table sounds they are marked as Backglass (BG) sound.  We treat like music.
void PinSound::PlayBGSound(int nVolume, const int loopcount, const bool usesame, const bool restart)
{
   // get the volume setting from VPX to calculate the real volume
   //int tableMusicVolume = g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "MusicVolume"s, (int)100);
   int volume = nVolume * ( (float)g_pplayer->m_MusicVolume / 100);

   PLOGI << "Loaded Sound File: " << m_szName << " BGSOUND: " << volume << " Table Music Volume: " << g_pplayer->m_MusicVolume;
   if (Mix_Playing(m_assignedChannel)) {
      if (restart || !usesame){ // stop and reload  
        
         Mix_HaltChannel(m_assignedChannel);
         Mix_Volume(m_assignedChannel, volume);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      }
   } 
   else { // not playing
      Mix_Volume(m_assignedChannel, volume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }
   
}

// Called to play the table sounds via pintable.cpp
void PinSound::Play(const float volume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
{
   // setup the struct for the effects processing
    m_mixEffectsData.pitch = pitch;
    m_mixEffectsData.randompitch = randompitch;
    m_mixEffectsData.front_rear_fade = front_rear_fade;

   // normalize volume -1 to +1 to 0 128 (MIX_MAX_VOLUME - 28).
   // -28 because we dont want to max the gain.. so its really 0-100 now 
   int nVolume = static_cast<int>((std::clamp(volume, -1.0f, 1.0f) + 1.0f) * 50.0f);
   
   // BG Sound is handled differently then table sounds.  These are BG sounds stored in the table (vpx file).
   if (m_outputTarget == SNDOUT_BACKGLASS) 
   {
      //adjust volume against the tables global sound setting
      nVolume =  nVolume * ( (float)g_pplayer->m_MusicVolume / 100);
      PlayBGSound(nVolume, loopcount, usesame, restart);
      return;
   }

   //adjust volume against the tables global sound setting
   nVolume =  nVolume * ( (float)g_pplayer->m_SoundVolume / 100);
   
   switch(m_SoundMode3D)
   {
      case SNDCFG_SND3D2CH:
         Play_SNDCFG_SND3D2CH(nVolume, randompitch, pitch, pan, front_rear_fade, loopcount, usesame, restart);
         break;
      case SNDCFG_SND3DALLREAR:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3DFRONTISREAR:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3DFRONTISFRONT:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3D6CH:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3DSSF:
         if (m_mixEffectsData.outputChannels != 8)
         {
            PLOGE << "Your sound device does not have the required number of channels to support this mode. <SNDCFG_SND3DSSF> ";
            break;
         }
          Play_SNDCFG_SND3DSSF(nVolume, randompitch, pitch, pan, front_rear_fade, loopcount, usesame, restart);
         break;
      default:
         PLOGE << "Invalid setting for 'Sound3D' in VPinball.ini...";
         break;
   }
}

void PinSound::Play_SNDCFG_SND3D2CH(int nVolume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
{

   // used to set pan volumes
   int leftVolume;
   int rightVolume;

   if(pan != 0) // only if pan is set
      CalculatePanVolumes(leftVolume, rightVolume, pan, nVolume);

      // debug stuff
      PLOGI << std::fixed << std::setprecision(7) << "Playing Sound: " << m_szName << " SoundOut (0=table, 1=bg): " << 
      (int) m_outputTarget << " nVol: " << nVolume << " pan: " << pan <<
      " Pitch: "<< pitch << " Random pitch: " << randompitch <<   " loopcount: " << loopcount << " usesame: " << 
      usesame <<  " Restart? " << restart;

   if (Mix_Playing(m_assignedChannel)) {
      if(pan != 0)
         Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      else
         Mix_Volume(m_assignedChannel, nVolume);

      if (restart || !usesame){ // stop and reload  
         //Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
         Mix_HaltChannel(m_assignedChannel);
         if(pan != 0)
            Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
         else
            Mix_Volume(m_assignedChannel, nVolume);
         // register the pitch effect.  must do this each time before PlayChannel
         //Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      }
   } 
   else { // not playing
      // register the pitch effect.  must do this each time before PlayChannel
      //Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
      if(pan != 0)
         Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      else
         Mix_Volume(m_assignedChannel, nVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }   
}

void PinSound::Play_SNDCFG_SND3DSSF(int nVolume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
   {

      
   // used to set pan volumes
   int leftVolume;
   int rightVolume;

   if(pan != 0) // only if pan is set
      CalculatePanVolumes(leftVolume, rightVolume, pan, nVolume);

      // debug stuff
      PLOGI << std::fixed << std::setprecision(7) << "Playing Sound: " << m_szName << " SoundOut (0=table, 1=bg): " << 
      (int) m_outputTarget << " nVol: " << nVolume << " pan: " << pan <<
      " Pitch: "<< pitch << " Random pitch: " << randompitch <<   " loopcount: " << loopcount << " usesame: " << 
      usesame <<  " Restart? " << restart;

   if (Mix_Playing(m_assignedChannel)) {
      if(pan != 0)
         Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      else
         Mix_Volume(m_assignedChannel, nVolume);

      if (restart || !usesame){ // stop and reload  
         //Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
         Mix_HaltChannel(m_assignedChannel);
         if(pan != 0)
            Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
         else
            Mix_Volume(m_assignedChannel, nVolume);
         // register the pitch effect.  must do this each time before PlayChannel
         //Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      }
   } 
   else { // not playing
      // register the pitch effect.  must do this each time before PlayChannel
      //Mix_RegisterEffect(m_assignedChannel, PinSound::PitchEffect, nullptr, &m_mixEffectsData);
      if(pan != 0)
         Mix_SetPanning(m_assignedChannel, leftVolume, rightVolume);
      else
         Mix_Volume(m_assignedChannel, nVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }
      
   }

// Called to stop table sounds...   S_REMOVE See if this is even called ever?
void PinSound::Stop() 
{
   Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
}

// Calculate the pan volume for each speaker based on the pintable value sent
// from vpiball pan ranges from -1.0 (left) over 0.0 (both) to 1.0 (right)
void PinSound::CalculatePanVolumes(int& leftVolume, int& rightVolume, const float &pan, int baseVolume)
{

   float nPan = clamp(pan, 0.0, 1.0);
      
   if (pan > 0) //favor to right
   {
      if (pan > .000773734f) // all right vol
      {
         rightVolume = baseVolume; 
         leftVolume = 0;
      }
      else if(pan > .0000001f) // 25 percent mark .0000185
                     
      {
         leftVolume = baseVolume  * .25;
         rightVolume = baseVolume * .75;
      } 
      else{ // center 50/50
         leftVolume = baseVolume  / 2;
         rightVolume = baseVolume / 2;
      } 
   }
   else{ // favor the left
      if (pan < - .000773734f) // all left
      {
         leftVolume = baseVolume; 
         rightVolume = 0;
      }
      else if(pan < - .0000185) // 25 percent mark
      {
         rightVolume = baseVolume  * .25;
         leftVolume = baseVolume * .75;
      } 
      else{ // center
         leftVolume = baseVolume  / 2;
         rightVolume = baseVolume / 2;
      } 
   }
   
    PLOGI << "volume: " << baseVolume << " pan: " << pan << " nPan: " << nPan 
          << " left: " << leftVolume << " right: " << rightVolume;
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
// In the table script when it uses 'PlayMusic'. These are typcially in the music folder.
// volume comes in as 0-1.   
bool PinSound::MusicInit(const string& szFileName, const float volume)
{
   m_outputTarget = SNDOUT_BACKGLASS;

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

         int nVolume = (volume * 100.0) * ( (float)g_pplayer->m_MusicVolume / 100);
         MusicVolume(nVolume);
         MusicPlay();
         PLOGI << "Loaded Music File: " << szFileName << " nVolume: " << nVolume <<
            " to OutputTarget(0=table, 1=BG): " << static_cast<int>(m_outputTarget); 
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

// volume range that comes in is 0-1
void PinSound::MusicVolume(const float volume)
{
   int nVolume = (volume * 100.0) * ( (float)g_pplayer->m_MusicVolume / 100);
   Mix_VolumeMusic(nVolume);
}

// Inits the SDL Audio Streaming interface 
// Used by VPinMAMEController and PUP
// volume range 0-1 from both vpinmame and pup
// NEEDS global volume control?  Hook to MusicVolume?
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
// NEEDS global volume control?  Hook to MusicVolume?
void PinSound::StreamVolume(const float volume)
{
  
   if (m_streamVolume != volume)
   {
      SDL_SetAudioStreamGain(m_pstream, volume);
      m_streamVolume = volume;
   }
}

// Windows UI?  Load sound into Sound Resource Manager?
PinSound *PinSound::LoadFile(const string& strFileName)
{
   PinSound * const pps = new PinSound();

   pps->m_szPath = strFileName;
   pps->m_szName = TitleFromFilename(strFileName);

   FILE *f;
   if (fopen_s(&f, strFileName.c_str(), "rb") != 0 || !f)
   {
      ShowError("Could not open sound file.");
      return nullptr;
   }
   fseek(f, 0, SEEK_END);
   pps->m_cdata = (int)ftell(f);
   fseek(f, 0, SEEK_SET);
   pps->m_pdata = new char[pps->m_cdata];
   fread_s(pps->m_pdata, pps->m_cdata, 1, pps->m_cdata, f);
   fclose(f);

   HRESULT res = pps->ReInitialize();

   if(res == S_OK)
      return pps;
   else
      return nullptr;
   
}

void PinSound::WipeAllExceptFrontMusicMixCB(void *udata, Uint8 *stream, int len) {

   PLOGI << "MUJSIC CB got called!";

}

// Static - adjust pitch function... Called when registered with Mix_RegisterEffect
// from vpinball pitch can be positive or negative and directly adds onto the standard sample frequency
// from vpinball randompitch ranges from 0.0 (no randomization) to 1.0 (vary between half speed to double speed)
void PinSound::PitchEffect(int chan, void *stream, int len, void *udata) {
   MixEffectsData* med = static_cast<MixEffectsData*>(udata); 
   if(med->pitch == 0 && med->randompitch == 0) // no need to resample
      return;
   
   float pitchRatio;

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

               float fractional_pos = 0.0f;

               auto cubic_interpolation = [](int16_t y0, int16_t y1, int16_t y2, int16_t y3, float t) -> int16_t {
                  float a = -0.5f * y0 + 1.5f * y1 - 1.5f * y2 + 0.5f * y3;
                  float b = y0 - 2.5f * y1 + 2.0f * y2 - 0.5f * y3;
                  float c = -0.5f * y0 + 0.5f * y2;
                  float d = y1;
                  float value = a * t * t * t + b * t * t + c * t + d;
                  
                  // Clamp to the valid range of int16_t
                  return static_cast<int16_t>(std::max<float>(-32768.0f, std::min<float>(32767.0f, value)));
               };

               for (int i = 1; i < num_input_samples - 2; ++i) { // Start at 1 and end at num_input_samples - 2 to ensure we have enough points
                  fractional_pos += pitchRatio;
                  while (fractional_pos >= 1.0f) {
                     fractional_pos -= 1.0f;

                     // Perform cubic interpolation
                     int16_t interpolated_sample = cubic_interpolation(
                           input_samples[i - 1], input_samples[i], input_samples[i + 1], input_samples[i + 2], fractional_pos
                     );

                     output_samples.push_back(interpolated_sample);
                  }
               }

               // Copy processed output samples back to the stream
               std::memset(stream, 0, len); // Clear the buffer first
               std::memcpy(stream, output_samples.data(), std::min(len, static_cast<int>(output_samples.size() * sizeof(int16_t))));
               break;
               }

      case(SDL_AUDIO_F32LE):
         {
            // Input and output buffer pointers
            float *input_samples = static_cast<float *>(stream);
            int num_input_samples = len / sizeof(float);

            // Output buffer
            std::vector<float> output_samples;
            output_samples.reserve(static_cast<size_t>(num_input_samples / pitchRatio));

            float fractional_pos = 0.0f;

            auto cubic_interpolation = [](float y0, float y1, float y2, float y3, float t) -> float {
               float a = -0.5f * y0 + 1.5f * y1 - 1.5f * y2 + 0.5f * y3;
               float b = y0 - 2.5f * y1 + 2.0f * y2 - 0.5f * y3;
               float c = -0.5f * y0 + 0.5f * y2;
               float d = y1;
               return a * t * t * t + b * t * t + c * t + d;
            };

            for (int i = 1; i < num_input_samples - 2; ++i) { // Start at 1 and end at num_input_samples - 2 to ensure we have enough points
               fractional_pos += pitchRatio;
               while (fractional_pos >= 1.0f) {
                  fractional_pos -= 1.0f;

                  // Perform cubic interpolation
                  float interpolated_sample = cubic_interpolation(
                        input_samples[i - 1], input_samples[i], input_samples[i + 1], input_samples[i + 2], fractional_pos
                  );

                  output_samples.push_back(interpolated_sample);
               }
            }

            // Copy processed output samples back to the stream
            std::memset(stream, 0, len); // Clear the buffer first
            std::memcpy(stream, output_samples.data(), std::min(len, static_cast<int>(output_samples.size() * sizeof(float))));
            break;
         }
      default:
         {
            PLOGE << "Could not identify audio format encoding size. Type: " << med->outputFormat;
            return;
         }
    }  
}

 std::string PinSound::getFileExt()
 {
   const size_t pos = m_szPath.find_last_of('.');
   if(pos == string::npos)
      return "";
   return m_szPath.substr(pos+1);
 }

// if the file is a Wav
uint16_t PinSound::getChannelCountWav() {
   struct WavHeader {
    char riff[4];              // "RIFF"
    uint32_t fileSize;         // File size - 8 bytes
    char wave[4];              // "WAVE"
    char fmtChunkMarker[4];    // "fmt "
    uint32_t fmtChunkSize;     // Size of fmt chunk
    uint16_t audioFormat;      // Audio format (1 = PCM)
    uint16_t numChannels;      // Number of channels
    uint32_t sampleRate;       // Sample rate
    uint32_t byteRate;         // Byte rate
    uint16_t blockAlign;       // Block align
    uint16_t bitsPerSample;    // Bits per sample
};
    // Check that the data is at least the size of the WavHeader
    if (m_cdata < sizeof(WavHeader)) {
        throw std::runtime_error("Invalid WAV data: too small to contain a valid header.");
    }
    const WavHeader* header = reinterpret_cast<const WavHeader*>(m_pdata);

    // Return the number of channels
    return header->numChannels;
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
	
}


