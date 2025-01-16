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


PinSound::PinSound(const Settings& settings)
{
   if (!isSDLAudioInitialized) {
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
}

//static - Setup up the sound device(s) and the mixer for each. Runs ones at the class level.
void PinSound::initSDLAudio() 
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
   //delete [] m_pdata;
   
 }

// CHANGE should really be called loadSound S_COMMENT
// Called by pintable.cpp, ....
HRESULT PinSound::ReInitialize() {
	UnInitialize();
  
   PLOGI << "Loading Sound File: " << m_szName << " to OutputTarget(0=table, 1=BG): " << static_cast<int>(m_outputTarget);

   // this may not be needed. Or at least righ now... S_REMOVE
   const SoundConfigTypes SoundMode3D = (m_outputTarget == SNDOUT_BACKGLASS) ? SNDCFG_SND3D2CH : (SoundConfigTypes)g_pvp->m_settings.LoadValueWithDefault(Settings::Player, "Sound3D"s, (int)SNDCFG_SND3D2CH);

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
    
    PLOGI << "Audio Spec: " << m_audioSpec.format << " channels: " << m_audioSpec.channels << " freq: " << m_audioSpec.freq;
    // all table sounds are mono in prep for 3d sound
    if (m_audioSpec.format != SDL_AUDIO_S16LE || m_audioSpec.channels != 1) // if not convert to mono
    {
      PLOGI << "None mono sound detected.  Converting: " << m_szName << "audiospec frormat: " << m_audioSpecMono.format;
      Uint8 *buffer;
      int bufferLength;
      PinSound::m_audioSpecMono.freq = m_audioSpec.freq; // set the freq to what it was in the org
      if (SDL_ConvertAudioSamples(&m_audioSpec, m_audioBuffer, m_audioLength, &m_audioSpecMono, &buffer, &bufferLength))
      {
         /* free(m_audioBuffer);
         m_audioBuffer = buffer;
         m_audioLength = bufferLength;
         m_audioSpec = m_audioSpecMono; */
      }
      else 
      {
         PLOGE << "Could not convert sound file to mono: " << m_szName;
      }

    }

    m_stream = SDL_OpenAudioDeviceStream(m_sdl_STD_idx, &m_audioSpec, NULL, NULL);
    if (!m_stream) {
        PLOGE << "SDL_OpenAudioDeviceStream error:  " << SDL_GetError();
        return E_FAIL;
    } 

    //testing
    //allocate swap buffers
    //m_audioLengthSwap = m_audioLength;
    //m_audioBufferSwap = new Uint8[m_audioLengthSwap];

    // by default the stream is paused.  Must unpause it to use.  ** Always appears to return false even though its successful
    SDL_ResumeAudioStreamDevice(m_stream); 


    
   // Testing S_REMOVE
  /*  Uint8* m_mixAudioBuffer = new Uint8[m_audioLength];
   //SDL_MixAudio(m_mixAudioBuffer, m_audioBuffer, SDL_AudioFormat(SDL_AUDIO_S16LE), m_audioLength, .5);
   //PLOGI << "Error: " << SDL_GetError(); 
   for (size_t i = 0; i < m_audioLength; i += 2) {  // 16-bit samples (2 bytes per sample)
        int16_t* sample = reinterpret_cast<int16_t*>(m_audioBuffer + i);

        // Scale the sample by volume factor
        int new_sample = static_cast<int>(*sample * .5);

        // Prevent clipping
        *sample = static_cast<int16_t>(std::clamp(new_sample, -32768, 32767));
   }
   SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
   SDL_Delay(5000); */

    // Remove this is for testing. S_REMOVE
    // this actually plays the sound!
    //if(m_szName == "DROPTARG")
    //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
    //SDL_Delay(5000);
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
   
   if (SDL_GetAudioStreamAvailable(m_stream) > 0) {
    // Data is available in the stream
     PLOGI << "Data still in stream...";
     AdjustVolume(volume, true);

     if (restart){
       PLOGI << "Stopping and restarting stream";
      //AdjustVolume(volume, true);
      Stop();
      AdjustVolume(volume, false);
      //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
      //SDL_ResumeAudioStreamDevice(m_stream); 
     }
   } 
   else { // not playing
      AdjustVolume(volume, false);
      //SDL_PutAudioStreamData(m_stream, m_audioBuffer, m_audioLength); // have to load audio into stream.  Dump it all
      //SDL_ResumeAudioStreamDevice(m_stream); 
   }
}

void PinSound::AdjustVolume(float volume, bool isPlaying) {
    Uint8 *buffer;
    Uint32 bufferLength;
    SDL_AudioFormat format;
    int channels;

   // taken from code.  The volume value appears to be in the range of 0 and 100? lots in .xx  
   volume = sqrtf(saturate(volume*(float)(1.0/100.)));
   PLOGI << "vol adjusted to: " << volume;

   
   if (isPlaying){

      // comp for last volume change to same sample
      volume = (volume / m_lastVolume);
      m_lastVolume = volume;


      SDL_PauseAudioStreamDevice(m_stream);
      SDL_AudioSpec dst_spec;
      SDL_GetAudioStreamFormat(m_stream, NULL, &dst_spec);
      format = dst_spec.format;
      channels = dst_spec.channels;
      int bytesLeftInStream = SDL_GetAudioStreamAvailable(m_stream);
      buffer = new Uint8[bytesLeftInStream];
      bufferLength = SDL_GetAudioStreamData(m_stream, buffer, bytesLeftInStream);
      PLOGI << "Data in stream: " << bytesLeftInStream;
      PLOGI << "Volume: " << volume << " AudioFormat: " << format << " Channels: " << channels ;
      EncodeVolume(buffer, bufferLength, format, channels, volume);

      // now we need to convert it back to input stream format if different.
      if (m_audioSpec.format != format || m_audioSpec.channels != channels)
      {
         PLOGI << "Not a matching sample!  Must convert: dst_spec: " << dst_spec.format << "src spec: " << m_audioSpec.format;
         Uint8 *tmpBuffer;
         int tmpBufferLength;
         bool test = SDL_ConvertAudioSamples(&dst_spec, buffer, bufferLength, &m_audioSpec, &tmpBuffer, &tmpBufferLength);
         SDL_ClearAudioStream(m_stream);
         SDL_PutAudioStreamData(m_stream, tmpBuffer, tmpBufferLength); // have to load audio into stream.  Dump it all
         SDL_ResumeAudioStreamDevice(m_stream);
         SDL_free(tmpBuffer);
      }
      else { // else put it in the stream directly without conversion to the output spec
         SDL_ClearAudioStream(m_stream);
         SDL_PutAudioStreamData(m_stream, buffer, bufferLength); // have to load audio into stream.  Dump it all
         SDL_ResumeAudioStreamDevice(m_stream);
      }
   }
   else 
   {
     m_lastVolume = volume; // set lastVolume used
     buffer = new Uint8[m_audioLength];
     memcpy(buffer, m_audioBuffer,m_audioLength); // copy the org sound in
     bufferLength = m_audioLength;
     format = m_audioSpec.format;
     channels = m_audioSpec.channels;
     PLOGI << "Volume: " << volume << " AudioFormat: " << format << " Channels: " << channels ;
     EncodeVolume(buffer, bufferLength, format, channels, volume);
     SDL_PutAudioStreamData(m_stream, buffer, bufferLength); // have to load audio into stream.  Dump it all
     SDL_ResumeAudioStreamDevice(m_stream); 
   }
   delete buffer;
}

void PinSound::EncodeVolume(Uint8 *buffer, int length, SDL_AudioFormat format, int channels, float volume)
{
  
   switch (format) 
   {
      case SDL_AUDIO_S16LE:
        if (channels = 1) // mono sound sample
        {
            for (size_t i = 0; i < length; i += 2) {  // 16-bit samples (2 bytes per sample)
                  int16_t* sample = reinterpret_cast<int16_t*>(buffer + i);

                  // Scale the sample by volume factor
                  int new_sample = static_cast<int>(*sample * volume);

                  // Prevent clipping
                  *sample = static_cast<int16_t>(std::clamp(new_sample, -32768, 32767));
            }
            }
         if (channels = 2) // stereo sound sample
         {
             for (size_t i = 0; i < length; i += 4) {  // 4 bytes per stereo frame (16-bit per channel)
               int16_t* left_sample  = reinterpret_cast<int16_t*>(buffer + i);     // Left channel
               int16_t* right_sample = reinterpret_cast<int16_t*>(buffer + i + 2); // Right channel

               // Scale both channels
               int new_left  = static_cast<int>(*left_sample * volume);
               int new_right = static_cast<int>(*right_sample * volume);

               // Clamp to prevent clipping
               *left_sample  = static_cast<int16_t>(std::clamp(new_left, -32768, 32767));
               *right_sample = static_cast<int16_t>(std::clamp(new_right, -32768, 32767));
            }

         }
        break;
      case SDL_AUDIO_F32LE:
         if (channels = 2) // stereo sound sample
         {
               PLOGI << "SDL_AUDIO_F32LE - 2 channels";
               float* samples = reinterpret_cast<float*>(buffer); // Interpret buffer as float array
               size_t sample_count = length / sizeof(float);      // Number of float samples

               for (size_t i = 0; i < sample_count; i++) {
                  samples[i] *= volume;  // Scale sample

                  // Optional: Prevent clipping if volume > 1.0f
                  samples[i] = std::clamp(samples[i], -1.0f, 1.0f);
               }
         }
         break;

   }
}


void PinSound::Stop() 
{
    //PLOGI << "Called";
    SDL_PauseAudioStreamDevice(m_stream);
    SDL_ClearAudioStream(m_stream);

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


