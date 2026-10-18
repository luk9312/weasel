#pragma once

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

// A Weasel color scheme generated from a Sogou Pinyin skin.
struct ImportedColorScheme {
  std::string id;
  std::string name;
  std::string author;
  // keys under preset_color_schemes/<id>/, values as YAML scalars
  std::vector<std::pair<std::string, std::string>> values;
};

// Unpacks a Sogou Pinyin skin (.ssf, either a plain zip or the encrypted
// format) into <user_dir>/skins/<skin id>/ and builds color schemes from its
// skin.ini, with separate background images for horizontal and vertical
// layouts when the skin has both.
bool ImportSsfSkin(const std::filesystem::path& ssf_path,
                   const std::filesystem::path& user_dir,
                   std::vector<ImportedColorScheme>* schemes,
                   std::wstring* error);
