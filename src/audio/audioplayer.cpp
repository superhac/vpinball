// license:GPLv3+

#include "core/stdafx.h"
#include "audio/audioplayer.h"
#include <SDL3_mixer/SDL_mixer.h>
#include <SDL3/SDL.h>
#include "audio/pinsound.h"

/*static*/ float convert2decibelvolume(const float volume) // 0..100 -> DSBVOLUME_MIN..DSBVOLUME_MAX (-10000..0) (db/log scale)
{
   PLOGV << "called";
   const float totalvolume = max(min(volume, 100.0f), 0.0f);
   const float decibelvolume = (totalvolume == 0.0f) ? DSBVOLUME_MIN : max(logf(totalvolume)*(float)(1000.0 / log(10.0)) - 2000.0f, (float)DSBVOLUME_MIN); // VP legacy conversion
   return decibelvolume;
}

AudioPlayer::AudioPlayer()
{
   PLOGI << "constructor";
   Settings settings = g_pvp->m_settings;
   ps = new PinSound(settings);
   
}

AudioPlayer::~AudioPlayer()
{
   if(m_pstream != nullptr)
      SDL_DestroyAudioStream(m_pstream);
   if(ps != nullptr)
       delete ps;
}

void AudioPlayer::MusicPause()
{
   if (m_stream)
   {
      if(g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);
      BASS_ChannelPause(m_stream);
   }
}

void AudioPlayer::MusicUnpause()
{
   if (m_stream)
   {
      if (g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);
      BASS_ChannelPlay(m_stream, 0);
   }
}

bool AudioPlayer::MusicActive()
{
  return ps->MusicActive();
}

/*void AudioPlayer::MusicEnd()
{
   if (m_stream)
   {
      if(g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);
      BASS_ChannelStop(m_stream);
   }
}*/

bool AudioPlayer::MusicInit(const string& szFileName, const float volume)
{

   PLOGI << "music? " << szFileName;
  
   return true;


   if (g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);

#ifndef __STANDALONE__
   const string& filename = szFileName;
#else
   const string filename = normalize_path_separators(szFileName);
#endif

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
      m_stream = BASS_StreamCreateFile(FALSE, path.c_str(), 0, 0, /*BASS_SAMPLE_LOOP*/0); //!! ?
      if (m_stream != 0)
         break;
   }

   if (m_stream == 0)
   {
      const int code = BASS_ErrorGetCode();
      string bla;
      ///BASS_ErrorMapCode(code, bla);
      g_pvp->MessageBox(("BASS music/sound library cannot load \"" + filename + "\" (error " + std::to_string(code) + ": " + bla + ')').c_str(), "Error", MB_ICONERROR);
      return false;
   }

   BASS_ChannelSetAttribute(m_stream, BASS_ATTRIB_VOL, volume);
   BASS_ChannelPlay(m_stream, 0);

   return true;
}

void AudioPlayer::MusicVolume(const float volume)
{
   PLOGI << "Called: volL " << volume;
  
}

bool AudioPlayer::SetMusicFile(const string& szFileName)
{
   PLOGI << "Called";
  
   return ps->SetMusicFile(szFileName);
   //return true;

}

void AudioPlayer::MusicPlay()
{
  ps->MusicPlay();
}

void AudioPlayer::MusicStop()
{
ps->MusicStop();
}

void AudioPlayer::MusicClose()
{
   PLOGI << "Called";

}

double AudioPlayer::GetMusicPosition()
{
   PLOGI << "Called";
   return 1;

   if (m_stream) {
      if(g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);

      return BASS_ChannelBytes2Seconds(m_stream, BASS_ChannelGetPosition(m_stream, BASS_POS_BYTE));
   }

   return -1;
}

void AudioPlayer::SetMusicPosition(double seconds)
{
   PLOGI << "Called";
   return;
   if (m_stream) {
      if(g_pvp->m_ps.bass_BG_idx != -1 && g_pvp->m_ps.bass_STD_idx != g_pvp->m_ps.bass_BG_idx) BASS_SetDevice(g_pvp->m_ps.bass_BG_idx);

      BASS_ChannelSetPosition(m_stream, BASS_ChannelSeconds2Bytes(m_stream, seconds), BASS_POS_BYTE);
   }
}

// called from VPinMAMEController
bool AudioPlayer::StreamInit(DWORD frequency, int channels, const float volume) 
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
void AudioPlayer::StreamUpdate(void* buffer, DWORD length) 
{
   SDL_PutAudioStreamData(m_pstream, buffer, length);
}

//called from VPinMAMEController
// Need to implement
void AudioPlayer::StreamVolume(const float volume)
{
   //PLOGI << "Called: vol: " << volume;
   //MusicVolume(volume);
}
