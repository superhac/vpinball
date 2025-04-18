#pragma once

#include "AssetSrc.h"
#include "Bitmap.h"

#include <map>
#include <filesystem>
#include <iostream>
#include <dirent.h>
#include <vector>
#include <string>
#include <cctype>
#include <optional>

class Font;

class AssetManager
{
public:
   AssetManager();
   ~AssetManager();

   void ClearAll();

   AssetSrc* ResolveSrc(const string& src, AssetSrc* pBaseSrc);
   Bitmap* GetBitmap(AssetSrc* pSrc);
   Font* GetFont(AssetSrc* pSrc);
   void* Open(AssetSrc* pSrc);
   const string& GetBasePath() { return m_szBasePath; }
   void SetBasePath(const string& szBasePath);

private:
   std::map<string, Bitmap*> m_cachedBitmaps;
   std::map<string, Font*> m_cachedFonts;

   string m_szBasePath;

   std::optional<std::string> fixPathFromMoveBack(const std::string& originalPath, int fixFromBack);
};
