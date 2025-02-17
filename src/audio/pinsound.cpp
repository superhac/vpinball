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
SDL_AudioSpec PinSound::m_audioSpecOutput;

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

      PinSound::initSDLAudio();
      isSDLAudioInitialized = true;

      // Set the output AudioSpec and display output settings of device
      Mix_QuerySpec(&m_mixEffectsData.outputFrequency, &m_mixEffectsData.outputFormat, &m_mixEffectsData.outputChannels);
      Mix_QuerySpec(&m_audioSpecOutput.freq, &m_audioSpecOutput.format, &m_audioSpecOutput.channels);
      
      PLOGI << "Output Device Settings: " << "Freq: " << m_mixEffectsData.outputFrequency << " Format (SDL_AudioFormat): " << m_mixEffectsData.outputFormat
      << " channels: " << m_mixEffectsData.outputChannels;

   }     
   // set the MixEffects output params that are used for resampling the incoming stream to callback.
   Mix_QuerySpec(&m_mixEffectsData.outputFrequency, &m_mixEffectsData.outputFormat, &m_mixEffectsData.outputChannels); 
}

PinSound::~PinSound()
{
      UnInitialize();
}

//static - Setup up the sound device(s) and the mixer for each. Runs once at the class level.
void PinSound::initSDLAudio() 
{
   string soundDeviceName;
   string soundDeviceBGName;
   bool good = m_settings.LoadValue(Settings::Player, "SoundDevice"s, soundDeviceName);
   good = m_settings.LoadValue(Settings::Player, "SoundDeviceBG"s, soundDeviceBGName);

    if (!good) // use the default SDL audio device
    {
      PLOGI << "Sound Device not set in VPinball.ini.  Using default";
      m_sdl_STD_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      m_sdl_BG_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
    }
    else{  // this is all because the device id's are random: https://github.com/libsdl-org/SDL/issues/12278
      vector<AudioDevice> allAudioDevices;
      PinSound::EnumerateAudioDevices(allAudioDevices);
      for (size_t i = 0; i < allAudioDevices.size(); ++i) {
         AudioDevice audioDevice = allAudioDevices.at(i);
         if (audioDevice.name == soundDeviceName)
         {
            m_sdl_STD_idx = audioDevice.id;
         }
         if (audioDevice.name == soundDeviceBGName)
         {
            m_sdl_BG_idx = audioDevice.id;
         }
      }

      if(m_sdl_STD_idx == -1) // we didn't find a matching name
      {
         PLOGE << "No sound device by that name found in VPinball.ini.  Using Default.";
         m_sdl_STD_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDevice"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
         m_sdl_BG_idx = m_settings.LoadValueWithDefault(Settings::Player, "SoundDeviceBG"s, (int) SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK);
      }
      
    }

      PinSound::m_SoundMode3D = (SoundConfigTypes) m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (SoundConfigTypes)SNDCFG_SND3D2CH);

      // set the global vpinball.. name should be changed for bass to sdl...
      g_pvp->m_ps.bass_BG_idx = m_sdl_BG_idx; // BG sounds
      g_pvp->m_ps.bass_STD_idx = m_sdl_STD_idx; // table sounds

      if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        PLOGE << "Failed to initialize SDL: " << SDL_GetError();
        return;         
      }
      
      // change the AudioSpec param when we know what sound format out we want.  or get from device
      if (!Mix_OpenAudio(m_sdl_STD_idx, NULL)) {
        PLOGE << "Failed to initialize SDl_MIXER: " << SDL_GetError();
        return;        
      }

      SDL_AudioSpec spec;
      int sample_frames;
      SDL_GetAudioDeviceFormat(m_sdl_STD_idx, &spec, &sample_frames);

      int chans = Mix_AllocateChannels(m_maxSDLMixerChannels); // set the max channel pool
      PLOGI << "SDL_mixer Allocated " << chans << " channels.";
}

 void PinSound::UnInitialize()
 {
      if(m_pMixChunkOrg != nullptr)
      {
         Mix_FreeChunk(m_pMixChunkOrg);
         m_pMixChunkOrg = nullptr;
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

   if(! (m_pMixChunkOrg = Mix_LoadWAV_IO(m_psdlIOStream, true)))
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

 /*   PLOGI << "Loaded Sound File: " << m_szName << " Sound Type: " << getFileExt() << 
      " # of Audio Channels: " << ( (getFileExt() =="wav") ? std::to_string(getChannelCountWav() ) : "Unknown" ) <<
      " Assigned Channel: " << m_assignedChannel << " SoundOut (0=table, 1=bg): " << (int)m_outputTarget; */

	return S_OK;
}

// Called to play the table sounds via pintable.cpp
void PinSound::Play(const float volume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
{
   // Clamp volume
   float minVol = .08f;  // some table sounds like rolling are extreaming low.  Set a minimum or you cant hear it.
   float nVolume = std::clamp(volume+minVol, 0.0f, 1.0f);
  
   // BG Sound is handled differently then table sounds.  These are BG sounds stored in the table (vpx file).
   if (m_outputTarget == SNDOUT_BACKGLASS) 
   {
      //adjust volume against the tables global sound setting
      nVolume =  (int) ( abs(volume) * 100); // ABS because some tables send negative volume??? e.g. Kiss stern.  Using mixer vol control. no float. 0-128. cap @ 100
      PlayBGSound(nVolume, loopcount, usesame, restart);
      return;
   }

   //adjust volume against the tables global sound setting
   nVolume =  nVolume * ( (float)g_pplayer->m_SoundVolume / 100);
   
   // setup the struct for the effects processing
   m_mixEffectsData.pitch = pitch;
   m_mixEffectsData.randompitch = randompitch;
   m_mixEffectsData.front_rear_fade = front_rear_fade;
   m_mixEffectsData.pan = pan;
   m_mixEffectsData.volume = volume;
   m_mixEffectsData.nVolume = nVolume;
   m_mixEffectsData.globalTableVolume = (float)g_pplayer->m_SoundVolume / 100;
  
   switch(PinSound::m_SoundMode3D)
   {
      case SNDCFG_SND3D2CH:
         Play_SNDCFG_SND3D2CH(nVolume, randompitch, pitch, pan, front_rear_fade, loopcount, usesame, restart);
         break;
      case SNDCFG_SND3DALLREAR:
         if (m_mixEffectsData.outputChannels < 4) // channel count must be at least 4.  Front and Rear
         {
            PLOGE << "Your sound device does not have the required number of channels to support this mode. <SND3DALLREAR> ";
            break;
         }
         Play_SNDCFG_SND3DALLREAR(nVolume, randompitch, pitch, pan, front_rear_fade, loopcount, usesame, restart);
         break;
      case SNDCFG_SND3DFRONTISREAR:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3DFRONTISFRONT:
         PLOGI << "Sound Mode not implemented yet.";
         break;
      case SNDCFG_SND3D6CH:
         // we just fall through to the SSF.  This mode is same but it used two different pan and fade algos.  No need to have two different ones now.
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

// These are BG sounds that are loaded in the table.  They show up in the windows versions Sound Manger.
// But instead of being table sounds they are marked as Backglass (BG) sound.  We treat like music.
void PinSound::PlayBGSound(float nVolume, const int loopcount, const bool usesame, const bool restart)
{
   //PLOGI << "PlayBG Sound File: " << m_szName << " BGSOUND nVolume: " << nVolume << " Table Music Volume: " << g_pplayer->m_MusicVolume;

   if (Mix_Playing(m_assignedChannel)) {
      if (restart || !usesame){ // stop and reload       
         Mix_HaltChannel(m_assignedChannel);
         Mix_Volume(m_assignedChannel, nVolume);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunkOrg, 0);
      }
   } 
   else { // not playing
      Mix_Volume(m_assignedChannel, nVolume);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunkOrg, 0);
   }
}

void PinSound::setPitch(int pitch, float randompitch)
{

   if(m_pMixChunk != nullptr) // free the last converted sample
   {
      Mix_FreeChunk(m_pMixChunk);
      m_pMixChunk = nullptr;
   }
   
   // check for pitch and resample or pass the orginial mixchunk if pitch didn't change
   if(pitch == 0 && randompitch == 0) // If the pitch isn't changed pass the orginal
   {
      m_pMixChunk = copyMixChunk(m_pMixChunkOrg);
   }
   else
   {
      Mix_Chunk *mixChunkConvert = (Mix_Chunk *)malloc(sizeof(Mix_Chunk));
      mixChunkConvert->allocated = 1; // you need this set or it won't get freed with Mix_FreeChunk
      mixChunkConvert->volume = 128;

      int newFreq = 0;

      if(randompitch > 0)
      {
         const float rndh = rand_mt_01();
         const float rndl = rand_mt_01();
         int freq = m_mixEffectsData.outputFrequency + (m_mixEffectsData.outputFrequency * randompitch * rndh * rndh) - (m_mixEffectsData.outputFrequency * 
           randompitch * rndl * rndl * 0.5f);
         newFreq = freq + pitch; // add the normal pitch in if its set
         //PLOGI << " random: new freq = " << newFreq;
      }
      else{ // just pitch is set
         newFreq = m_mixEffectsData.outputFrequency + pitch;
      }

      //PLOGI << "Channel: " << m_assignedChannel << " Current freq: " << m_mixEffectsData.outputFrequency << " Pitch: " << pitch << " Random pitch: " << randompitch << " Ending new freq = " << newFreq;

      SDL_AudioSpec audioSpecConvert;
      Mix_QuerySpec(&audioSpecConvert.freq, &audioSpecConvert.format, &audioSpecConvert.channels);
      audioSpecConvert.freq = newFreq;

      // comvert orginal sample to the new freq
      SDL_ConvertAudioSamples(&m_audioSpecOutput, m_pMixChunkOrg->abuf, m_pMixChunkOrg->alen, &audioSpecConvert, &mixChunkConvert->abuf, (int *) &mixChunkConvert->alen);

      // now convert it back to orginal output AudioSpec
      m_pMixChunk = new Mix_Chunk();
      m_pMixChunk->volume = 128;
      m_pMixChunk->allocated = 1; // you need this set or it won't get freed with Mix_FreeChunk
      SDL_ConvertAudioSamples(&audioSpecConvert, mixChunkConvert->abuf, (int ) mixChunkConvert->alen, &m_audioSpecOutput, &m_pMixChunk->abuf, (int *) &m_pMixChunk->alen);
      
      Mix_FreeChunk(mixChunkConvert);
   }
}

void PinSound::Play_SNDCFG_SND3DALLREAR(float nVolume, const float randompitch, const int pitch, 
   const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
{
     // used to set pan volumes
     float leftVolume;
     float rightVolume;
  
        /* PLOGI << std::fixed << std::setprecision(7) << "Playing Sound: " << m_szName << " SoundOut (0=table, 1=bg): " << 
        (int) m_outputTarget << " nVol: " << nVolume << " pan: " << pan <<
        " Pitch: "<< pitch << " Random pitch: " << randompitch  << " front_rear_fade: " << front_rear_fade <<   " loopcount: " << loopcount << " usesame: " << 
        usesame <<  " Restart? " << restart; */
  
     if (Mix_Playing(m_assignedChannel)) {
        if (restart || !usesame){ // stop and reload  
           Mix_HaltChannel(m_assignedChannel);
           setPitch(pitch, randompitch);
           // register the effects.  must do this each time before PlayChannel and once the sound is done its unregistered automaticly
           Mix_RegisterEffect(m_assignedChannel, PinSound::MoveFrontToRearEffect, nullptr, &m_mixEffectsData);
           Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
        }
     } 
     else { // not playing
        setPitch(pitch, randompitch);
        // register the effects.  must do this each time before PlayChannel and once the sound is done its unregistered automaticly
        Mix_RegisterEffect(m_assignedChannel, PinSound::MoveFrontToRearEffect, nullptr, &m_mixEffectsData);
        Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
     } 

}

void PinSound::Play_SNDCFG_SND3D2CH(float nVolume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
{

   // used to set pan volumes
   float leftVolume;
   float rightVolume;

      /* PLOGI << std::fixed << std::setprecision(7) << "Playing Sound: " << m_szName << " SoundOut (0=table, 1=bg): " << 
      (int) m_outputTarget << " nVol: " << nVolume << " pan: " << pan <<
      " Pitch: "<< pitch << " Random pitch: " << randompitch  << " front_rear_fade: " << front_rear_fade <<   " loopcount: " << loopcount << " usesame: " << 
      usesame <<  " Restart? " << restart; */

   if (Mix_Playing(m_assignedChannel)) {
      if (restart || !usesame){ // stop and reload  
         Mix_HaltChannel(m_assignedChannel);
         setPitch(pitch, randompitch);
         // register the effects.  must do this each time before PlayChannel and once the sound is done its unregistered automaticly
         Mix_RegisterEffect(m_assignedChannel, PinSound::Pan2ChannelEffect, nullptr, &m_mixEffectsData);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      }
   } 
   else { // not playing
      // register the effects.  must do this each time before PlayChannel and once the sound is done its unregistered automaticly
      setPitch(pitch, randompitch);
      Mix_RegisterEffect(m_assignedChannel, PinSound::Pan2ChannelEffect, nullptr, &m_mixEffectsData);
      Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
   }   
}

void PinSound::Play_SNDCFG_SND3DSSF(float nVolume, const float randompitch, const int pitch, 
               const float pan, const float front_rear_fade, const int loopcount, const bool usesame, const bool restart)
   {
      /*  PLOGI << std::fixed << std::setprecision(7) << "SSF Playing Sound: " << m_szName << " SoundOut (0=table, 1=bg): " << 
         (int) m_outputTarget << " nVol: " << nVolume << " pan: " << pan <<
         " Pitch: "<< pitch << " Random pitch: " << randompitch << " front_rear_fade: " << front_rear_fade << " loopcount: " << loopcount << " usesame: " << 
         usesame <<  " Restart? " << restart; */

      if (Mix_Playing(m_assignedChannel)) {
   
         if (restart || !usesame){ // stop and reload  
            Mix_HaltChannel(m_assignedChannel);
            setPitch(pitch, randompitch);
            // register the pitch effect.  must do this each time before PlayChannel.  When the sound is done playing its automaticlly unregisted.
            Mix_RegisterEffect(m_assignedChannel, PinSound::SSFEffect, nullptr, &m_mixEffectsData);
            Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
         }
      } 
      else { // not playing
         setPitch(pitch, randompitch);
         // register the pitch effect.  must do this each time before PlayChannel.  When the sound is done playing its automaticlly unregisted.
         Mix_RegisterEffect(m_assignedChannel, PinSound::SSFEffect, nullptr, &m_mixEffectsData);
         Mix_PlayChannel(m_assignedChannel, m_pMixChunk, 0);
      }
      
   }

// Called to stop table sound seperate from the table doing it. I think its used to stop all sounds so its called in a loop. Windows UI?
 void PinSound::Stop() 
 {
     Mix_FadeOutChannel(m_assignedChannel, 300); // fade out in 300ms.  Also halts channel when done
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
         /* PLOGI << "Loaded Music File: " << szFileName << " nVolume: " << nVolume <<
            " to OutputTarget(0=table, 1=BG): " << static_cast<int>(m_outputTarget);  */
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
   SDL_AudioSpec audioSpec;
   audioSpec.freq = frequency;
   audioSpec.format =  SDL_AUDIO_S16LE;
   audioSpec.channels = channels;

   float nVolume = volume  * ( (float) g_pplayer->m_MusicVolume / 100);  
   m_pstream = SDL_OpenAudioDeviceStream(m_sdl_BG_idx, &audioSpec, NULL, NULL);

   if(m_pstream)
   {
      SDL_SetAudioStreamGain(m_pstream, nVolume);
      SDL_ResumeAudioStreamDevice(m_pstream); // it always stops paused
      return true;
   }
   else{
      PLOGE << "Failed to load stream: "  << SDL_GetError();
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
   //PLOGI << "STREAM VOL";
   float nVolume = volume  * ( (float) g_pplayer->m_MusicVolume / 100);
   if (m_streamVolume != volume)
   {
      SDL_SetAudioStreamGain(m_pstream, nVolume);
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

Mix_Chunk* PinSound::copyMixChunk(const Mix_Chunk* original) {
   if (!original) return nullptr;

   // Allocate a new Mix_Chunk
   Mix_Chunk* copy = new Mix_Chunk;
   copy->allocated = original->allocated;
   copy->alen = original->alen;
   copy->volume = original->volume;

   // Allocate memory for audio buffer
   copy->abuf = new Uint8[original->alen];
   std::memcpy(copy->abuf, original->abuf, original->alen);

   return copy;
}

//static
void PinSound::calcPan(float& leftPanRatio, float& rightPanRatio, float adjustedVolRatio, float pan)
{
    // Normalize pan from range [-3, 3] to [-1, 1]
    pan = pan / 3.0f;

    // Ensure pan is within -1 to 1 (in case of floating-point errors)
    pan = std::clamp(pan, -1.0f, 1.0f);

    // Use a more standard panning formula that keeps values within range
    float leftFactor = 0.5f * (1.0f - pan);  // Left decreases as pan increases
    float rightFactor = 0.5f * (1.0f + pan); // Right increases as pan increases

    leftPanRatio = adjustedVolRatio * leftFactor;
    rightPanRatio = adjustedVolRatio * rightFactor;

    // Ensure the values are properly clamped
    leftPanRatio = std::clamp(leftPanRatio, 0.0f, 1.0f);
    rightPanRatio = std::clamp(rightPanRatio, 0.0f, 1.0f);

    //PLOGI << "Pan: " << pan << " AdjustedVolRatio: " << adjustedVolRatio << " Left: " << leftPanRatio << " Right: " << rightPanRatio;
}

//static
void PinSound::calcFade(float leftPanRatio, float rightPanRatio, float fadeRatio, float& frontLeft, float& frontRight, float& rearLeft, float& rearRight)
{
   // Clamp fadeRatio to the range [0.0, 2.5]
   fadeRatio = std::max(0.0f, std::min(2.5f, fadeRatio));

   // Calculate front and rear weights (linear fade)
   float rearWeight = std::max(0.0f, 2.5f - fadeRatio) / 2.5f; // 1 at fadeRatio=0, 0 at fadeRatio=2.5
   float frontWeight = std::min(2.5f, fadeRatio) / 2.5f;        // 0 at fadeRatio=0, 1 at fadeRatio=2.5

   // Apply panning ratios
   frontLeft  = frontWeight * leftPanRatio;
   frontRight = frontWeight * rightPanRatio;
   rearLeft   = rearWeight * leftPanRatio;
   rearRight  = rearWeight * rightPanRatio;

   //PLOGI << "FadeRatio: " << fadeRatio << " FrontLeft: " << frontLeft << " FrontRight: " << frontRight << " RearLeft: " << rearLeft << " RearRight: " << rearRight;
}

// This is a replacement function for PanTo3D() for sound effect panning (audio x-axis).
// It performs the same calculations but maps the resulting values to an area of the 3D 
// sound stage that has the expected panning effect for this application. It is written 
// in a long form to facilitate tweaking the formulas.  *njk*

//static
float PinSound::PanSSF(float pan)
{
	// This math could probably be simplified but it is kept in long form
	// to aide in fine tuning and clarity of function.

	// Clip the pan input range to -1.0 to 1.0
	float x = clamp(pan, -1.f, 1.f);

	// Rescale pan range from an exponential [-1,0] and [0,1] to a linear [-1.0, 1.0]
	// Do not avoid values close to zero like PanTo3D() does as that
	// prevents the middle range of the exponential curves converting back to 
	// a linear scale (which would leave a gap in the center of the range).
	// This basically undoes the Pan() fading function in the table scripts.

	x = (x < 0.0f) ? -powf(-x, 0.1f) : powf(x, 0.1f);

	// Increase the pan range from [-1.0, 1.0] to [-3.0, 3.0] to improve the surround sound fade effect

	x *= 3.0f;

	// BASS pan effect is much better than VPX 10.6/DirectSound3d but it
	// could still stand a little enhancement to exaggerate the effect.
	// The effect goal is to place slingshot effects almost entirely left/right
	// and flipper effects in the cross fade region (louder on their corresponding
	// sides but still audible on the opposite side..)

	// Rescale [-3.0,0.0) to [-3.00,-2.00] and [0,3.0] to [2.00,3.00]

	// Reminder: Linear Conversion Formula [o1,o2] to [n1,n2]
	// x' = ( (x - o1) / (o2 - o1) ) * (n2 - n1) + n1
	//
	// We retain the full formulas below to make it easier to tweak the values.
	// The compiler will optimize away the excess math.

	if (x >= 0.0f)
		x = ((x -  0.0f) / (3.0f -  0.0f)) * ( 3.0f -  2.0f) +  2.0f;
	else
		x = ((x - -3.0f) / (0.0f - -3.0f)) * (-2.0f - -3.0f) + -2.0f;

	// Clip the pan output range to 3.0 to -3.0
	//
	// This probably can never happen but is here in case the formulas above
	// change or there is a rounding issue.

	if (x > 3.0f)
		x = 3.0f;
	else if (x < -3.0f)
		x = -3.0f;

	// If the final value is sufficiently close to zero it causes sound to come from
	// all speakers and lose it's positional effect. We scale well away from zero
	// above but will keep this check to document the effect or catch the condition
	// if the formula above is later changed to one that can result in x = 0.0.

	// NOTE: This no longer seems to be the case with VPX 10.7/BASS

	// HOWEVER: Weird things still happen NEAR 0.0 or if both x and z are at 0.0.
	//          So we keep the fix here with wider margins to prevent that case.
	//          The current formula won't produce values in this weird range.

	if (fabsf(x) < 0.1f)
		x = (x < 0.0f) ? -0.1f : 0.1f;

	return x;
}

// This is a replacement function for PanTo3D() for sound effect fading (audio z-axis).
// It performs the same calculations but maps the resulting values to 
// an area of the 3D sound stage that has the expected fading
// effect for this application. It is written in a long form to facilitate tweaking the 
// values (which turned out to be more straightforward than originally coded). *njk*

//static
float PinSound::FadeSSF(float front_rear_fade)
{
	float z;

	// Clip the fade input range to -1.0 to 1.0

	if (front_rear_fade < -1.0f)
		z = -1.0f;
	else if (front_rear_fade > 1.0f)
		z = 1.0f;
	else
		z = front_rear_fade;

	// Rescale fade range from an exponential [0,-1] and [0,1] to a linear [-1.0, 1.0]
	// Do not avoid values close to zero like PanTo3D() does at this point as that
	// prevents the middle range of the exponential curves converting back to 
	// a linear scale (which would leave a gap in the center of the range).
	// This basically undoes the AudioFade() fading function in the table scripts.	

	z = (z < 0.0f) ? -powf(-z, 0.1f) : powf(z, 0.1f);

	// Increase the fade range from [-1.0, 1.0] to [-3.0, 3.0] to improve the surround sound fade effect

	z *= 3.0f;

	// Rescale fade range from [-3.0,3.0] to [0.0,-2.5] in an attempt to remove all sound from
	// the surround sound front (backbox) speakers and place them close to the surround sound
	// side (cabinet rear) speakers.
	//
	// Reminder: Linear Conversion Formula [o1,o2] to [n1,n2]
	// z' = ( (z - o1) / (o2 - o1) ) * (n2 - n1) + n1
	//
	// We retain the full formulas below to make it easier to tweak the values.
	// The compiler will optimize away the excess math.

	// Rescale to -2.5 instead of -3.0 to further push sound away from rear channels
	z = ((z - -3.0f) / (3.0f - -3.0f)) * (-2.5f - 0.0f) + 0.0f;

	// With BASS the above scaling is sufficient to keep the playfield sounds out of 
	// the backbox. However playfield sounds are heavily weighted to the rear channels. 
	// For BASS we do a simple scale of the top third [0,-1.0] BY 0.10 to favor
	// the side channels. This is better than we could do in VPX 10.6 where z just
	// had to be set to 0.0 as there was no fade range that didn't leak to the backbox
	// as well.
	
	if (z > -1.0f)
		z = z / 10.0f;

	// Clip the fade output range to 0.0 to -3.0
	//
	// This probably can never happen but is here in case the formulas above
	// change or there is a rounding issue. A result even slightly greater
	// than zero can bleed to the backbox speakers.

	if (z > 0.0f)
		z = 0.0f;
	else if (z < -3.0f)
		z = -3.0f;

	// If the final value is sufficiently close to zero it causes sound to come from
	// all speakers on some systems and lose it's positional effect. We do use 0.0 
	// above and could set the safe value there. Instead will keep this check to document 
	// the effect or catch the condition if the formula/conditions above are later changed

	// NOTE: This no longer seems to be the case with VPX 10.7/BASS

	// HOWEVER: Weird things still happen near 0.0 or if both x and z are at 0.0.
	//          So we keep the fix here to prevent that case. This does push a tiny bit 
	//          of audio to the rear channels but that is perfectly ok.

	if (fabsf(z) < 0.0001f)
		z = -0.0001f;
	
	return fabsf(z); // I changed this to get a postive range from 0 to 2.5. not sure why before they returned negative
}

// static
// pans the FL and FR channels.  The built in Mix_SetPanning does not work on 2+ channels: https://github.com/libsdl-org/SDL_mixer/issues/665 
void PinSound::Pan2ChannelEffect(int chan, void *stream, int len, void *udata) {

   MixEffectsData *med = static_cast<MixEffectsData *> (udata);
    // pan vols ratios for left and right
    float leftPanRatio;
    float rightPanRatio;

    switch (med->outputFormat)
    {
       case (SDL_AUDIO_S16LE):
          {
             int16_t* samples = static_cast<int16_t*>(stream);
             int total_samples = len / sizeof(int16_t);
             int channels = med->outputChannels;
             int frames = total_samples / channels; // Each frame divided by samples
 
             calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));

             // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
            for (int frame = 0; frame < frames; ++frame) {
               int index = frame * channels;
         
               // Apply volume gains to Front Left and Right channels
               samples[index] = (samples[index] * leftPanRatio);  //  FL
               samples[index + 1] = (samples[index+1] * rightPanRatio); // FR
            }
            break;
         }
            case (SDL_AUDIO_F32LE):
               {
                  float* samples = static_cast<float*>(stream);
                  int total_samples = len / sizeof(float);
                  int channels = med->outputChannels;
                  int frames = total_samples / channels; // Each frame has divided by channels
      
                  calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));

                   // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
               for (int frame = 0; frame < frames; ++frame) {
                  int index = frame * channels;
            
                  // Apply volume gains to Front Left and Right channels
                  samples[index] = (samples[index] * leftPanRatio);  //  FL
                  samples[index + 1] = (samples[index+1] * rightPanRatio); // FR
               }
                  break;  
               }
               default:
                  {
                     PLOGE << "unknown audio format..";
                     return;
                  }
   }
}

// static
// pans the FL and FR channels.  The built in Mix_SetPanning does not work on 2+ channels: https://github.com/libsdl-org/SDL_mixer/issues/665 
void PinSound::MoveFrontToRearEffect(int chan, void *stream, int len, void *udata) {

   MixEffectsData *med = static_cast<MixEffectsData *> (udata);
    // pan vols ratios for left and right
    float leftPanRatio;
    float rightPanRatio;

    switch (med->outputFormat)
    {
       case (SDL_AUDIO_S16LE):
          {
             int16_t* samples = static_cast<int16_t*>(stream);
             int total_samples = len / sizeof(int16_t);
             int channels = med->outputChannels;
             int frames = total_samples / channels; // Each frame divided by samples
 
             calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));

             // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
            for (int frame = 0; frame < frames; ++frame) {
               int index = frame * channels;
               
               if(channels == 4) // 4 channels (quad) layout: FL, FR, BL, BR
               {
                  // Apply volume gains and copy them to rear
                  samples[index+2] = (samples[index] * leftPanRatio); // copy FL to BL
                  samples[index+3] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
               } 
               else if(channels == 5) //5 channels (4.1) layout: FL, FR, LFE, BL, BR
               {
                  // Apply volume gains and copy them to rear
                  samples[index+3] = (samples[index] * leftPanRatio); // copy FL to BL
                  samples[index+4] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
               }
               else if(channels == 6) // 6 channels (5.1) layout: FL, FR, FC, LFE, BL, BR (last two can also be SL, SR)
               {
                  // Apply volume gains and copy them to rear
                  samples[index+4] = (samples[index] * leftPanRatio); // copy FL to BL
                  samples[index+5] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
               }
               else if(channels == 7) // 7 channels (6.1) layout: FL, FR, FC, LFE, BC, SL, SR
               {
                  // Apply volume gains and copy them to rear
                  samples[index+5] = (samples[index] * leftPanRatio); // copy FL to BL
                  samples[index+6] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
               }
               else if(channels == 8) // 8 channels (7.1) layout: FL, FR, FC, LFE, BL, BR, SL, SR
               {
                  // Apply volume gains and copy them to rear
                  samples[index+4] = (samples[index] * leftPanRatio); // copy FL to BL
                  samples[index+5] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
               }

               // wipe front channels
               samples[index]   =  (0);
               samples[index+1] =  (0);
            }
            break;
         }
            case (SDL_AUDIO_F32LE):
               {
                  float* samples = static_cast<float*>(stream);
                  int total_samples = len / sizeof(float);
                  int channels = med->outputChannels;
                  int frames = total_samples / channels; // Each frame has divided by channels
      
                  calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));
                  for (int frame = 0; frame < frames; ++frame) {
                     int index = frame * channels;
               
                     
                     if(channels == 4) // 4 channels (quad) layout: FL, FR, BL, BR
                     {
                        // Apply volume gains and copy them to rear
                        samples[index+2] = (samples[index] * leftPanRatio); // copy FL to BL
                        samples[index+3] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
                     } 
                     else if(channels == 5) //5 channels (4.1) layout: FL, FR, LFE, BL, BR
                     {
                        // Apply volume gains and copy them to rear
                        samples[index+3] = (samples[index] * leftPanRatio); // copy FL to BL
                        samples[index+4] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
                     }
                     else if(channels == 6) // 6 channels (5.1) layout: FL, FR, FC, LFE, BL, BR (last two can also be SL, SR)
                     {
                        // Apply volume gains and copy them to rear
                        samples[index+4] = (samples[index] * leftPanRatio); // copy FL to BL
                        samples[index+5] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
                     }
                     else if(channels == 7) // 7 channels (6.1) layout: FL, FR, FC, LFE, BC, SL, SR
                     {
                        // Apply volume gains and copy them to rear
                        samples[index+5] = (samples[index] * leftPanRatio); // copy FL to BL
                        samples[index+6] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
                     }
                     else if(channels == 8) // 8 channels (7.1) layout: FL, FR, FC, LFE, BL, BR, SL, SR
                     {
                        // Apply volume gains and copy them to rear
                        samples[index+4] = (samples[index] * leftPanRatio); // copy FL to BL
                        samples[index+5] = (samples[index + 1] * rightPanRatio); // COPY FR to BR
                     }
      
                     // wipe front channels
                     samples[index]   =  (0);
                     samples[index+1] =  (0);
                  }
                  break;  
               }
               default:
                  {
                     PLOGE << "unknown audio format..";
                     return;
                  }
   }
}

// static
void PinSound::SSFEffect(int chan, void *stream, int len, void *udata) {
   // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
   MixEffectsData *med = static_cast<MixEffectsData *> (udata);

   // pan vols ratios for left and right
   float leftPanRatio;
   float rightPanRatio;

   // calc the fade
   float sideLeft;   // rear of table -1 
   float sideRight;
   float rearLeft;   // front  of table + 1
   float rearRight;

   switch (med->outputFormat)
   {
      case (SDL_AUDIO_S16LE):
         {
            int16_t* samples = static_cast<int16_t*>(stream);
            int total_samples = len / sizeof(int16_t);
            int channels = med->outputChannels;
            int frames = total_samples / channels; // Each frame divided by channels

            calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));
            calcFade(leftPanRatio, rightPanRatio, PinSound::FadeSSF(med->front_rear_fade), rearLeft, rearRight, sideLeft, sideRight);

            // cap all vol not to be over 1.  Over and you get distorition.
            sideLeft = clamp(sideLeft, 0.f, 1.f);
            sideRight = clamp(sideRight, 0.f, 1.f);
            rearLeft = clamp(rearLeft, 0.f, 1.f);
            rearRight = clamp(rearRight, 0.f, 1.f);

            // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
            for (int frame = 0; frame < frames; ++frame) {
               int index = frame * channels;

               // copy the sound sample from Front to Back and Side channels.
               samples[index + 4] = (samples[index]);   // COPY FL to BL
               samples[index + 5] = (samples[index+1]); // Copy FR to BR
               samples[index + 6] = (samples[index]);   // Copy FL to SL 
               samples[index + 7] = (samples[index+1]); // Copy FR to SR
         
               // Apply volume gains to back and side channels
               samples[index + 4] = (samples[index+4] * rearLeft);  //  BL
               samples[index + 5] = (samples[index+5] * rearRight); // BR
               samples[index + 6] = (samples[index+6] * sideLeft);  // SL 
               samples[index + 7] = (samples[index+7] * sideRight); // SR
               
               // wipe front channels
               samples[index]   =  (0);
               samples[index+1] =  (0);
            }
            break;
         }
      case (SDL_AUDIO_F32LE):
         {
            float* samples = static_cast<float*>(stream);
            int total_samples = len / sizeof(float);
            int channels = med->outputChannels;
            int frames = total_samples / channels; // Each frame has 8 samples (one per channel)

            calcPan(leftPanRatio, rightPanRatio, med->nVolume, PinSound::PanSSF(med->pan));
            calcFade(leftPanRatio, rightPanRatio, PinSound::FadeSSF(med->front_rear_fade), rearLeft, rearRight, sideLeft, sideRight);

            // 8 channels (7.1): FL, FR, FC, LFE, BL, BR, SL, SR
            for (int frame = 0; frame < frames; ++frame) {
               int index = frame * channels;

               // copy the sound sample from Front to Back and Side channels.
               samples[index + 4] = (samples[index]);   // COPY FL to BL
               samples[index + 5] = (samples[index+1]); // Copy FR to BR
               samples[index + 6] = (samples[index]);   // Copy FL to SL 
               samples[index + 7] = (samples[index+1]); // Copy FR to SR
         
               // Apply volume gains to back and side channels
               samples[index + 4] = (samples[index+4] * rearLeft);  //  BL
               samples[index + 5] = (samples[index+5] * rearRight); // BR
               samples[index + 6] = (samples[index+6] * sideLeft);  // SL 
               samples[index + 7] = (samples[index+7] * sideRight); // SR
               
               // wipe front channels
               samples[index]   =  (0);
               samples[index+1] =  (0);
            }
            break;
         }
      default:
         {
            PLOGE << "unknown audio format..";
            return;
         }
   }

   //PLOGI << " rearLeft: " << rearLeft << " rearRight: " << rearRight << " sideLeft: " << sideLeft << " sideRight: " << sideRight;
   return;
}

// static
// get a sound file's extension
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

