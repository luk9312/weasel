#include "stdafx.h"
#include "SsfImporter.h"
#include <WeaselUtility.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <map>
#include <bcrypt.h>
#include "MinizConfig.h"
#include "third_party/miniz/miniz.h"

#pragma comment(lib, "bcrypt.lib")

namespace {

// lower-case file name -> content
using SkinFiles = std::map<std::wstring, std::string>;
// lower-case section -> lower-case key -> value
using Ini = std::map<std::wstring, std::map<std::wstring, std::wstring>>;

// AES-256-CBC key and IV of encrypted .ssf files, as found by
// https://github.com/fkxxyz/ssfconv
const unsigned char kSsfKey[32] = {
    0x52, 0x36, 0x46, 0x1A, 0xD3, 0x85, 0x03, 0x66, 0x90, 0x45, 0x16,
    0x28, 0x79, 0x03, 0x36, 0x23, 0xDD, 0xBE, 0x6F, 0x03, 0xFF, 0x04,
    0xE3, 0xCA, 0xD5, 0x7F, 0xFC, 0xA3, 0x50, 0xE4, 0x9E, 0xD9};
const unsigned char kSsfIv[16] = {0xE0, 0x7A, 0xAD, 0x35, 0xE0, 0x90,
                                  0xAA, 0x03, 0x8A, 0x51, 0xFD, 0x05,
                                  0xDF, 0x8C, 0x5D, 0x0F};

std::wstring ToLower(std::wstring text) {
  std::transform(text.begin(), text.end(), text.begin(),
                 [](wchar_t c) { return (wchar_t)std::towlower(c); });
  return text;
}

std::wstring Trim(const std::wstring& text) {
  const size_t begin = text.find_first_not_of(L" \t\r\n");
  if (begin == std::wstring::npos)
    return std::wstring();
  const size_t end = text.find_last_not_of(L" \t\r\n");
  return text.substr(begin, end - begin + 1);
}

std::wstring DecodeCodePage(const std::string& text, UINT code_page) {
  if (text.empty())
    return std::wstring();
  const int len = MultiByteToWideChar(code_page, 0, text.data(),
                                      (int)text.size(), nullptr, 0);
  std::wstring result(len, L'\0');
  if (len > 0)
    MultiByteToWideChar(code_page, 0, text.data(), (int)text.size(), &result[0],
                        len);
  return result;
}

std::wstring DecodeUtf16Le(const std::string& data, size_t offset) {
  std::wstring result;
  for (size_t i = offset; i + 1 < data.size(); i += 2)
    result.push_back((wchar_t)((uint8_t)data[i] | ((uint8_t)data[i + 1] << 8)));
  return result;
}

// skin.ini is usually UTF-16LE; old skins may use GBK
std::wstring DecodeText(const std::string& data) {
  if (data.size() >= 2 && (uint8_t)data[0] == 0xFF && (uint8_t)data[1] == 0xFE)
    return DecodeUtf16Le(data, 2);
  if (data.size() >= 3 && data.compare(0, 3, "\xEF\xBB\xBF") == 0)
    return DecodeCodePage(data.substr(3), CP_UTF8);
  if (data.size() >= 2 && data[1] == 0)
    return DecodeUtf16Le(data, 0);
  return DecodeCodePage(data, 936);
}

// keep only a plain file name, so that nothing is written outside the skin
// folder
std::wstring SafeFileName(const std::wstring& name) {
  const size_t slash = name.find_last_of(L"/\\");
  std::wstring base =
      slash == std::wstring::npos ? name : name.substr(slash + 1);
  if (base.empty() || base == L"." || base == L".." ||
      base.find(L':') != std::wstring::npos)
    return std::wstring();
  return base;
}

bool AesCbcDecrypt(const std::string& in, std::string* out) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  bool ok = false;
  if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM,
                                                 nullptr, 0)) &&
      BCRYPT_SUCCESS(BCryptSetProperty(
          alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
          (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
      BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
          alg, &key, nullptr, 0, (PUCHAR)kSsfKey, (ULONG)sizeof(kSsfKey), 0))) {
    // the payload is not padded; ignore a trailing partial block, if any
    const ULONG len = (ULONG)(in.size() / 16 * 16);
    unsigned char iv[sizeof(kSsfIv)];
    memcpy(iv, kSsfIv, sizeof(iv));
    out->assign(len, '\0');
    ULONG written = 0;
    ok = len > 0 &&
         BCRYPT_SUCCESS(BCryptDecrypt(key, (PUCHAR)in.data(), len, nullptr, iv,
                                      (ULONG)sizeof(iv), (PUCHAR) & (*out)[0],
                                      len, &written, 0));
    out->resize(written);
  }
  if (key)
    BCryptDestroyKey(key);
  if (alg)
    BCryptCloseAlgorithmProvider(alg, 0);
  return ok;
}

bool ReadU32(const std::string& data, size_t offset, size_t* value) {
  if (offset > data.size() || data.size() - offset < 4)
    return false;
  const auto* p = reinterpret_cast<const uint8_t*>(data.data() + offset);
  *value = (size_t)p[0] | ((size_t)p[1] << 8) | ((size_t)p[2] << 16) |
           ((size_t)p[3] << 24);
  return true;
}

// Encrypted format: "Skin" + 4 bytes, then AES-256-CBC over (4 bytes +
// zlib stream). The inflated data is a file table: total size, size of the
// offset table, offsets; each entry is (name size, UTF-16LE name, content
// size, content).
bool UnpackEncrypted(const std::string& raw, SkinFiles* files) {
  std::string decrypted;
  if (raw.size() <= 8 || !AesCbcDecrypt(raw.substr(8), &decrypted) ||
      decrypted.size() <= 4)
    return false;
  size_t size = 0;
  void* inflated =
      tinfl_decompress_mem_to_heap(decrypted.data() + 4, decrypted.size() - 4,
                                   &size, TINFL_FLAG_PARSE_ZLIB_HEADER);
  if (!inflated)
    return false;
  const std::string data(static_cast<const char*>(inflated), size);
  mz_free(inflated);
  size_t table_size = 0;
  if (!ReadU32(data, 4, &table_size))
    return false;
  for (size_t i = 0; i + 4 <= table_size; i += 4) {
    size_t entry = 0, name_size = 0, content_size = 0;
    if (!ReadU32(data, 8 + i, &entry) || !ReadU32(data, entry, &name_size) ||
        name_size > data.size() - entry - 4)
      return false;
    const size_t name_offset = entry + 4;
    const size_t content_offset = name_offset + name_size + 4;
    if (!ReadU32(data, name_offset + name_size, &content_size) ||
        content_size > data.size() - content_offset)
      return false;
    const std::wstring name =
        SafeFileName(DecodeUtf16Le(data.substr(name_offset, name_size), 0));
    if (!name.empty())
      (*files)[ToLower(name)] = data.substr(content_offset, content_size);
  }
  return !files->empty();
}

bool UnpackZip(const std::string& raw, SkinFiles* files) {
  mz_zip_archive zip;
  memset(&zip, 0, sizeof(zip));
  if (!mz_zip_reader_init_mem(&zip, raw.data(), raw.size(), 0))
    return false;
  const mz_uint count = mz_zip_reader_get_num_files(&zip);
  for (mz_uint i = 0; i < count; ++i) {
    mz_zip_archive_file_stat stat;
    if (!mz_zip_reader_file_stat(&zip, i, &stat) || stat.m_is_directory)
      continue;
    // names are GBK unless the UTF-8 flag is set
    const bool utf8 = (stat.m_bit_flag & (1 << 11)) != 0;
    const std::wstring name =
        SafeFileName(DecodeCodePage(stat.m_filename, utf8 ? CP_UTF8 : 936));
    if (name.empty())
      continue;
    size_t size = 0;
    void* content = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
    if (!content)
      continue;
    (*files)[ToLower(name)].assign(static_cast<const char*>(content), size);
    mz_free(content);
  }
  mz_zip_reader_end(&zip);
  return !files->empty();
}

Ini ParseIni(const std::wstring& text) {
  Ini ini;
  std::wstring section;
  size_t start = 0;
  while (start < text.size()) {
    size_t end = text.find(L'\n', start);
    if (end == std::wstring::npos)
      end = text.size();
    const std::wstring line = Trim(text.substr(start, end - start));
    start = end + 1;
    if (line.empty() || line[0] == L';' || line[0] == L'#')
      continue;
    if (line[0] == L'[') {
      section = ToLower(Trim(line.substr(1, line.find(L']') - 1)));
      continue;
    }
    const size_t eq = line.find(L'=');
    if (eq != std::wstring::npos)
      ini[section][ToLower(Trim(line.substr(0, eq)))] =
          Trim(line.substr(eq + 1));
  }
  return ini;
}

std::wstring Get(const Ini& ini, const wchar_t* section, const wchar_t* key) {
  const auto s = ini.find(section);
  if (s == ini.end())
    return std::wstring();
  const auto v = s->second.find(key);
  return v == s->second.end() ? std::wstring() : v->second;
}

std::vector<int> ParseInts(const std::wstring& text) {
  std::vector<int> values;
  const wchar_t* p = text.c_str();
  while (*p) {
    wchar_t* end = nullptr;
    const long value = wcstol(p, &end, 10);
    if (end == p) {
      ++p;
      continue;
    }
    values.push_back((int)value);
    p = end;
  }
  return values;
}

// Sogou colors are 0xBBGGRR, same as Weasel's default color format (abgr)
bool ParseColor(const std::wstring& text, uint32_t* color) {
  if (text.empty())
    return false;
  wchar_t* end = nullptr;
  const unsigned long value = wcstoul(text.c_str(), &end, 16);
  if (end == text.c_str())
    return false;
  *color = (uint32_t)value & 0xffffff;
  return true;
}

std::string WeaselColor(uint32_t color, uint32_t alpha = 0xff) {
  char buffer[16];
  snprintf(buffer, sizeof(buffer), "0x%02X%06X", alpha, color & 0xffffff);
  return buffer;
}

std::string MakeSkinId(const std::wstring& stem) {
  std::string ascii;
  for (wchar_t c : stem) {
    if (c < 128 && std::iswalnum(c))
      ascii.push_back((char)std::towlower(c));
    else if (!ascii.empty() && ascii.back() != '_')
      ascii.push_back('_');
  }
  while (!ascii.empty() && ascii.back() == '_')
    ascii.pop_back();
  if (ascii.size() > 24)
    ascii.resize(24);
  // FNV-1a of the file name keeps ids of skins with similar names apart
  uint32_t hash = 2166136261u;
  for (wchar_t c : stem) {
    hash ^= (uint32_t)c;
    hash *= 16777619u;
  }
  char suffix[16];
  snprintf(suffix, sizeof(suffix), "%06x", hash & 0xffffff);
  return "sogou_" + (ascii.empty() ? std::string() : ascii + "_") + suffix;
}

int At(const std::vector<int>& values, size_t i) {
  return i < values.size() ? values[i] : 0;
}

// map a single-image Sogou scheme ([Scheme_H1] / [Scheme_V1]) to
// <key>, <key>_slice and <key>_padding
bool AddBackImage(const Ini& ini,
                  const wchar_t* section,
                  const std::string& key,
                  const std::string& skin_dir,
                  const SkinFiles& files,
                  ImportedColorScheme* scheme) {
  const std::wstring pic = ToLower(Get(ini, section, L"pic"));
  if (pic.empty() || !files.count(pic))
    return false;
  // layout_*: mode, fixed size at start, fixed size at end
  const auto h = ParseInts(Get(ini, section, L"layout_horizontal"));
  const auto v = ParseInts(Get(ini, section, L"layout_vertical"));
  // *_marge: top, bottom, left, right
  const auto pinyin = ParseInts(Get(ini, section, L"pinyin_marge"));
  const auto zhongwen = ParseInts(Get(ini, section, L"zhongwen_marge"));
  char slice[64], padding[64];
  snprintf(slice, sizeof(slice), "%d, %d, %d, %d", At(h, 1), At(v, 1), At(h, 2),
           At(v, 2));
  snprintf(padding, sizeof(padding), "%d, %d, %d, %d",
           (std::max)(At(pinyin, 2), At(zhongwen, 2)), At(pinyin, 0),
           (std::max)(At(pinyin, 3), At(zhongwen, 3)), At(zhongwen, 1));
  scheme->values.emplace_back(key, skin_dir + "/" + wtou8(pic));
  scheme->values.emplace_back(key + "_slice", slice);
  scheme->values.emplace_back(key + "_padding", padding);
  return true;
}

bool IsGenericName(const std::wstring& name) {
  const std::wstring lower = ToLower(name);
  return lower.empty() || lower == L"new" || lower == L"skin" ||
         lower == L"default";
}

}  // namespace

bool ImportSsfSkin(const std::filesystem::path& ssf_path,
                   const std::filesystem::path& user_dir,
                   std::vector<ImportedColorScheme>* schemes,
                   std::wstring* error) {
  schemes->clear();
  std::ifstream in(ssf_path, std::ios::binary);
  const std::string raw((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
  if (raw.empty()) {
    *error = L"无法读取这个文件。";
    return false;
  }
  SkinFiles files;
  const bool unpacked = raw.compare(0, 4, "Skin") == 0
                            ? UnpackEncrypted(raw, &files)
                            : UnpackZip(raw, &files);
  if (!unpacked) {
    *error = L"无法解开这个皮肤包，格式不认识或文件已损坏。";
    return false;
  }
  const auto ini_file = files.find(L"skin.ini");
  if (ini_file == files.end()) {
    *error = L"皮肤包里没有 skin.ini，可能不是搜狗输入法电脑版的皮肤。";
    return false;
  }
  const Ini ini = ParseIni(DecodeText(ini_file->second));

  const std::wstring stem = ssf_path.stem().wstring();
  const std::string id = MakeSkinId(stem);
  const std::filesystem::path dir = user_dir / L"skins" / u8tow(id);
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  for (const auto& file : files) {
    std::ofstream out(dir / file.first, std::ios::binary | std::ios::trunc);
    out.write(file.second.data(), (std::streamsize)file.second.size());
    if (!out) {
      *error = L"无法写入皮肤文件夹：" + dir.wstring();
      return false;
    }
  }

  std::wstring name = Get(ini, L"general", L"skin_name");
  if (IsGenericName(name))
    name = stem;
  uint32_t pinyin = 0, first = 0, other = 0, hint = 0;
  ParseColor(Get(ini, L"display", L"pinyin_color"), &pinyin);
  ParseColor(Get(ini, L"display", L"zhongwen_first_color"), &first);
  ParseColor(Get(ini, L"display", L"zhongwen_color"), &other);
  if (!ParseColor(Get(ini, L"display", L"comphint_color"), &hint))
    hint = other;

  ImportedColorScheme base;
  base.id = id;
  base.name = wtou8(name);
  base.author = wtou8(Get(ini, L"general", L"skin_author"));
  // Sogou only recolors the first candidate, so highlights stay transparent;
  // back_color and border_color still matter for tips and fallback drawing
  base.values = {
      {"back_color", WeaselColor(0xffffff)},
      {"border_color", WeaselColor(pinyin)},
      {"text_color", WeaselColor(pinyin)},
      {"hilited_text_color", WeaselColor(pinyin)},
      {"hilited_back_color", WeaselColor(0xffffff, 0)},
      {"candidate_text_color", WeaselColor(other)},
      {"candidate_back_color", WeaselColor(0xffffff, 0)},
      {"label_color", WeaselColor(other)},
      {"comment_text_color", WeaselColor(hint)},
      {"hilited_candidate_text_color", WeaselColor(first)},
      {"hilited_candidate_back_color", WeaselColor(0xffffff, 0)},
      {"hilited_label_color", WeaselColor(first)},
      {"hilited_comment_text_color", WeaselColor(hint)},
      {"hilited_mark_color", WeaselColor(0, 0)},
  };

  // one scheme carries both images; the panel picks one by layout direction
  const std::string skin_dir = "skins/" + id;
  AddBackImage(ini, L"scheme_h1", "back_image", skin_dir, files, &base);
  AddBackImage(ini, L"scheme_v1", "back_image_vertical", skin_dir, files,
               &base);
  schemes->push_back(base);
  return true;
}
