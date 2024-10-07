#include <filesystem>
#include <string>
#include <stdio.h>
#include <windows.h>
#if defined(VERSION_DLL_VERSION) || defined(WINHTTP_DLL_VERSION)
#include "./QuickDllProxy/DllProxy.h"
#endif
#include "./Detours/detours.h"
#include "./SimpleIni/SimpleIni.h"

// HandleException function used to display any Quick DLL Proxy errors
#if defined(VERSION_DLL_VERSION) || defined (WINHTTP_DLL_VERSION)
void HandleException(DllProxy::ErrorCode code)
{
  // Switch based on the error code
  // Note: std::format adds a significant amount of additional code into the DLL so instead we are using stdio functions
  //       to compose the messages
  wchar_t message[256];
  switch (code)
  {
  case DllProxy::ErrorCode::InvalidModuleBase:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: Unable to query base address of this DLL", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  case DllProxy::ErrorCode::InvalidModuleHeaders:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: Invalid DOS, NT, or export directory headers", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  case DllProxy::ErrorCode::VirtualProtectFailed:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: A call to VirtualProtect failed", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  case DllProxy::ErrorCode::LibraryNotFound:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: Failed to load original module for proxying", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  case DllProxy::ErrorCode::ExportNotFound:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: Failed to locate an exported function in the original module", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  case DllProxy::ErrorCode::ExportNotResolved:
    // Display error message
    swprintf_s(message, L"Quick DLL Proxy reported the following error:\nCode: %u\n"
      "Message: A proxy export was called but a real function pointer wasn't resolved yet", code);
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    break;
  }
}

// Fix use of __unaligned in the Quick DLL Proxy for x86 DLLs
#if defined(_M_IX86)
#define __unaligned
#endif

// Needed define and include statements for the Quick DLL Proxy
// See: https://github.com/Nukem9/QuickDllProxy
#if defined(VERSION_DLL_VERSION)
#define DLL_PROXY_EXPORT_LISTING_FILE "version_exports.inc" // List of exported functions
#elif defined(WINHTTP_DLL_VERSION)
#define DLL_PROXY_EXPORT_LISTING_FILE "winhttp_exports.inc" // List of exported functions
#endif
#define DLL_PROXY_TLS_CALLBACK_AUTOINIT                     // Automatically initialize
#define DLL_PROXY_EXCEPTION_CALLBACK HandleException        // Custom error handler
#define DLL_PROXY_DECLARE_IMPLEMENTATION                    // Add the actual implementation
#include "./QuickDllProxy/DllProxy.h"
#endif

// Define and/or declare needed global variables
static int(WINAPI* WindowsGetDeviceCaps)(HDC hdc, int index) = GetDeviceCaps;
static BOOL(WINAPI* WindowsEnumDisplaySettingsA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode) =
  EnumDisplaySettingsA;
static BOOL(WINAPI* WindowsEnumDisplaySettingsW)(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode) =
  EnumDisplaySettingsW;
static BOOL(WINAPI* WindowsEnumDisplaySettingsExA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode,
  DWORD dwFlags) = EnumDisplaySettingsExA;
static BOOL(WINAPI* WindowsEnumDisplaySettingsExW)(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode,
  DWORD dwFlags) = EnumDisplaySettingsExW;
HMODULE gModule;
bool gIniFileError;
CSimpleIni gIniFile;
struct EDSDeviceMapStruct
{
  bool wildcard;
  DWORD mode;
  std::wstring section;
};
std::multimap<std::wstring, EDSDeviceMapStruct> gEDSDeviceMap;

// GetIniFile function
static void LoadIniFile()
{
  // Get the full path to this DLL
  std::wstring path(MAX_PATH, 0);
  if (GetModuleFileName(gModule, &path[0], MAX_PATH) == 0)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to get DLL file path", L"Spoof Resolution", MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return;
  }

  // Remove the file name from the path and replace it with spoofres.ini
  path.erase(path.rfind(std::filesystem::path::preferred_separator) + 1);
  path += L"spoofres.ini";

  // Check if the ini file does not exist
  if (!std::filesystem::exists(path))
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to locate spoofres.ini file", L"Spoof Resolution", MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return;
  }

  // Open the ini file
  gIniFile.SetUnicode();
  if (gIniFile.LoadFile(path.c_str()) < 0)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to open spoofres.ini file", L"Spoof Resolution", MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return;
  }
}

// SpoofGDCResolution function
int SpoofGDCResolution(int value, int index)
{
  // Check if we encountered any ini file errors before
  if (gIniFileError)
    return value;

  // Check if the ini file is empty
  if (gIniFile.IsEmpty())
  {
    // Load the ini file
    LoadIniFile();
  }

  // Load the resolution information from the ini file
  // Note: we load all of the reolution information from the ini file before assigning any of it to the passed in
  //   pointers to avoid partially spoofing the resolution information if an exception is thrown during loading
  std::unique_ptr<int> spoofedValue = std::unique_ptr<int>(nullptr);
  try
  {
    if (index == HORZRES && gIniFile.KeyExists(L"GDC", L"Width"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile.GetValue(L"GDC", L"Width")));
    else if (index == VERTRES && gIniFile.KeyExists(L"GDC", L"Height"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile.GetValue(L"GDC", L"Height")));
    else if (index == BITSPIXEL && gIniFile.KeyExists(L"GDC", L"BitsPerPixel"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile.GetValue(L"GDC", L"BitsPerPixel")));
    else if (index == VREFRESH && gIniFile.KeyExists(L"GDC", L"Frequency"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile.GetValue(L"GDC", L"Frequency")));
  }
  catch (std::invalid_argument)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return value;
  }
  catch (std::out_of_range)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return value;
  }

  // Spoof the resolution information
  if (spoofedValue != nullptr)
  {
    value = *spoofedValue;

    #if defined(TEST_VERSION) || defined(VERBOSE_TEST_VERSION)
    // Show message
    std::wstring message = L"Spoofed resolution for index ";
    if (index == HORZRES)
      message += std::format(L"HORZRES with the following details:\n\nWidth = {:d}", *spoofedValue);
    else if (index == VERTRES)
      message += std::format(L"VERTRES with the following details:\n\nHeight = {:d}", *spoofedValue);
    else if (index == BITSPIXEL)
      message += std::format(L"BITSPIXEL with the following details:\n\nBits Per Pixel = {:d}", *spoofedValue);
    else if (index == VREFRESH)
      message += std::format(L"VREFRESH with the following details:\n\nFrequency = {:d}", *spoofedValue);
    MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
    #endif
  }

  return value;
}

// DetouredGetDeviceCaps function
int WINAPI DetouredGetDeviceCaps(HDC hdc, int index)
{
  // Call the real GetDeviceCaps function
  int value = WindowsGetDeviceCaps(hdc, index);

  #if defined(VERBOSE_TEST_VERSION)
  // Show message
  MessageBox(NULL, std::format(L"Detoured GetDeviceCaps function called with the following parameters:\n\nindex = {:d}",
    index).c_str(), L"Spoof Resolution", MB_OK);
  #endif

  // Spoof the resolution
  value = SpoofGDCResolution(value, index);

  return value;
}

// SpoofEDSResolution function
BOOL SpoofEDSResolution(BOOL valuesPopulated, LPCWSTR deviceName, DWORD modeNumber, DWORD* fields, DWORD* width,
  DWORD* height, DWORD* bitsPerPixel, DWORD* frequency, DWORD* flags, POINTL* position, DWORD* orientation)
{
  // Check if we encountered any ini file errors before
  if (gIniFileError)
    return FALSE;

  // Check if the ini file is empty
  if (gIniFile.IsEmpty())
  {
    // Load the ini file
    LoadIniFile();
  }

  // Check if the device map is empty
  if (gEDSDeviceMap.empty())
  {
    // Load all of the ini file sections
    CSimpleIni::TNamesDepend sections;
    gIniFile.GetAllSections(sections);
    if (sections.empty())
    {
      // Show an error message and set the ini file error flag
      MessageBox(NULL, L"Failed to load sections from spoofres.ini file", L"Spoof Resolution", MB_OK | MB_ICONERROR);
      gIniFileError = true;

      return FALSE;
    }

    // Loop through the sections
    for (CSimpleIni::Entry& section : sections)
    {
      // Get the section name
      std::wstring sectionName = section.pItem;

      // Check if the section name does not contain at least two | characters
      if (std::count_if(sectionName.begin(), sectionName.end(), [](const WCHAR c) { return c == L'|'; }) < 2)
        continue;

      // Get the type part of the section name
      std::wstring typePart(sectionName);
      typePart.erase(typePart.find(L'|'));

      // Check if this is not an EDS type section
      if (typePart != L"EDS")
        continue;

      // Get the device name and mode number parts of the section name
      std::wstring deviceNamePart(sectionName);
      deviceNamePart.erase(0, deviceNamePart.find(L'|') + 1);
      deviceNamePart.erase(deviceNamePart.rfind(L'|'));
      std::wstring modeNumberPart(sectionName);
      modeNumberPart.erase(0, modeNumberPart.rfind(L'|') + 1);

      // Populate the device map
      try
      {
        if (modeNumberPart == L"*")
          gEDSDeviceMap.insert({ deviceNamePart, { true, 0, sectionName } });
        else if (modeNumberPart == L"Current")
          gEDSDeviceMap.insert({ deviceNamePart, { false, ENUM_CURRENT_SETTINGS, sectionName } });
        else if (modeNumberPart == L"Registry")
          gEDSDeviceMap.insert({ deviceNamePart, { false, ENUM_REGISTRY_SETTINGS, sectionName } });
        else
          gEDSDeviceMap.insert({ deviceNamePart, { false, std::stoul(modeNumberPart), sectionName } });
      }
      catch (std::invalid_argument)
      {
        // Show an error message and set the ini file error flag
        MessageBox(NULL, L"Failed to parse section names in spoofres.ini file", L"Spoof Resolution",
          MB_OK | MB_ICONERROR);
        gIniFileError = true;

        return FALSE;
      }
      catch (std::out_of_range)
      {
        // Show an error message and set the ini file error flag
        MessageBox(NULL, L"Failed to parse section names in spoofres.ini file", L"Spoof Resolution",
          MB_OK | MB_ICONERROR);
        gIniFileError = true;

        return FALSE;
      }
    }
  }

  // Load the range of values for this device from the device map
  // Note: range is of type std::pair<std::multimap<std::wstring, DeviceMapStruct>::iterator,
  //   std::multimap<std::wstring, DeviceMapStruct>::iterator>
  auto range = gEDSDeviceMap.equal_range(L"*");
  if (range.first == range.second)
    range = gEDSDeviceMap.equal_range(deviceName);
  if (range.first == range.second)
  {
    #if defined(VERBOSE_TEST_VERSION)
    // Show message
    MessageBox(NULL, std::format(L"No ini file section found for device {}", deviceName).c_str(), L"Spoof Resolution",
      MB_OK);
    #endif

    return FALSE;
  }

  // Find the key/value pair for this mode number
  // Note: pair is of type std::multimap<std::wstring, DeviceMapStruct>::iterator
  // Note: the mode number wildcard is only considered if the valuesPopulated bool is true which indicates that this is
  //   a valid mode number
  auto pair = std::find_if(range.first, range.second,
    [&](const auto& pair) { return (valuesPopulated && pair.second.wildcard) || pair.second.mode == modeNumber; });
  if (pair == range.second)
  {
    #if defined(VERBOSE_TEST_VERSION)
    // Show message
    if (valuesPopulated)
      MessageBox(NULL, std::format(L"No ini file section found for device {} and mode number {:d}", deviceName,
        modeNumber).c_str(), L"Spoof Resolution", MB_OK);
    #endif

    return FALSE;
  }

  // Load the resolution information from the ini file
  // Note: we load all of the reolution information from the ini file before assigning any of it to the passed in
  //   pointers to avoid partially spoofing the resolution information if an exception is thrown during loading
  std::unique_ptr<DWORD> spoofedWidth = std::unique_ptr<DWORD>(nullptr);
  std::unique_ptr<DWORD> spoofedHeight = std::unique_ptr<DWORD>(nullptr);
  std::unique_ptr<DWORD> spoofedBitsPerPixel = std::unique_ptr<DWORD>(nullptr);
  std::unique_ptr<DWORD> spoofedFrequency = std::unique_ptr<DWORD>(nullptr);
  std::unique_ptr<DWORD> spoofedFlags = std::unique_ptr<DWORD>(nullptr);
  std::unique_ptr<POINTL> spoofedPosition = std::unique_ptr<POINTL>(nullptr);
  std::unique_ptr<DWORD> spoofedOrientation = std::unique_ptr<DWORD>(nullptr);
  try
  {
    if (width != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"Width"))
      spoofedWidth = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(), L"Width")));
    if (height != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"Height"))
      spoofedHeight = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(), L"Height")));
    if (bitsPerPixel != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"BitsPerPixel"))
      spoofedBitsPerPixel = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(),
        L"BitsPerPixel")));
    if (frequency != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"Frequency"))
      spoofedFrequency = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(),
        L"Frequency")));
    if (flags != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"Flags"))
      spoofedFlags = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(), L"Flags")));
    if (position != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"PositionX") &&
      gIniFile.KeyExists(pair->second.section.c_str(), L"PositionY"))
    {
      spoofedPosition = std::make_unique<POINTL>();
      spoofedPosition->x = std::stoul(gIniFile.GetValue(pair->second.section.c_str(), L"PositionX"));
      spoofedPosition->y = std::stoul(gIniFile.GetValue(pair->second.section.c_str(), L"PositionY"));
    }
    if (orientation != NULL && gIniFile.KeyExists(pair->second.section.c_str(), L"Orientation"))
      spoofedOrientation = std::make_unique<DWORD>(std::stoul(gIniFile.GetValue(pair->second.section.c_str(),
        L"Orientation")));
  }
  catch (std::invalid_argument)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return FALSE;
  }
  catch (std::out_of_range)
  {
    // Show an error message and set the ini file error flag
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFileError = true;

    return FALSE;
  }

  // Spoof the resolution information
  if (spoofedWidth != nullptr)
  {
    *width = *spoofedWidth;
    *fields |= DM_PELSWIDTH;
  }
  if (spoofedHeight != nullptr)
  {
    *height = *spoofedHeight;
    *fields |= DM_PELSHEIGHT;
  }
  if (spoofedBitsPerPixel != nullptr)
  {
    *bitsPerPixel = *spoofedBitsPerPixel;
    *fields |= DM_BITSPERPEL;
  }
  if (spoofedFrequency != nullptr)
  {
    *frequency = *spoofedFrequency;
    *fields |= DM_DISPLAYFREQUENCY;
  }
  if (spoofedFlags != nullptr)
  {
    *flags = *spoofedFlags;
    *fields |= DM_DISPLAYFLAGS;
  }
  if (spoofedPosition != nullptr)
  {
    position->x = spoofedPosition->x;
    position->y = spoofedPosition->y;
    *fields |= DM_POSITION;
  }
  if (spoofedOrientation != nullptr)
  {
    *orientation = *spoofedOrientation;
    *fields |= DM_DISPLAYORIENTATION;
  }

  #if defined(TEST_VERSION) || defined(VERBOSE_TEST_VERSION)
  // Show message
  std::wstring message = std::format(L"Spoofed resolution for device {} and mode number ", deviceName);
  if (modeNumber == ENUM_CURRENT_SETTINGS)
    message += L"ENUM_CURRENT_SETTINGS with the following details:\n";
  else if (modeNumber == ENUM_REGISTRY_SETTINGS)
    message += L"ENUM_REGISTRY_SETTINGS with the following details:\n";
  else
    message += std::format(L"{:d} with the following details:\n", modeNumber);
  if (spoofedWidth != nullptr)
    message += std::format(L"\nWidth = {:d}", *spoofedWidth);
  if (spoofedHeight != nullptr)
    message += std::format(L"\nHeight = {:d}", *spoofedHeight);
  if (spoofedBitsPerPixel != nullptr)
    message += std::format(L"\nBits Per Pixel = {:d}", *spoofedBitsPerPixel);
  if (spoofedFrequency != nullptr)
    message += std::format(L"\nFrequency = {:d}", *spoofedFrequency);
  if (spoofedFlags != nullptr)
    message += std::format(L"\nFlags = {:d}", *spoofedFlags);
  if (spoofedPosition != nullptr)
    message += std::format(L"\nPosition X = {:d}\nPosition Y = {:d}", spoofedPosition->x, spoofedPosition->y);
  if (spoofedOrientation != nullptr)
    message += std::format(L"\nOrientation = {:d}", *spoofedOrientation);
  MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
  #endif

  return TRUE;
}

// DetouredEnumDisplaySettingsA function
BOOL WINAPI DetouredEnumDisplaySettingsA(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode)
{
  // Call the real EnumDisplaySettingsA function
  BOOL devModePopulated = WindowsEnumDisplaySettingsA(lpszDeviceName, iModeNum, lpDevMode);

  // Convert the device name to a wide character string
  uint16_t deviceNameLength = MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, NULL, 0);
  std::wstring deviceName(deviceNameLength, 0);
  MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, &deviceName[0], deviceNameLength);
  deviceName.pop_back();

  #if defined(VERBOSE_TEST_VERSION)
  // Show message
  std::wstring message = std::format(L"Detoured EnumDisplaySettingsA function called with the following parameters:\n"
    "\nlpszDeviceName = {}\niModeNum = ", deviceName);
  if (iModeNum == ENUM_CURRENT_SETTINGS)
    message += L"ENUM_CURRENT_SETTINGS";
  else if (iModeNum == ENUM_REGISTRY_SETTINGS)
    message += L"ENUM_REGISTRY_SETTINGS";
  else
    message += std::format(L"{:d}", iModeNum);
  MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
  #endif

  // Spoof the resolution
  BOOL resolutionSpoofed = SpoofEDSResolution(devModePopulated, deviceName.c_str(), iModeNum, &lpDevMode->dmFields,
    &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency,
    &lpDevMode->dmDisplayFlags, NULL, NULL);

  return devModePopulated || resolutionSpoofed;
}

// DetouredEnumDisplaySettingsW function
BOOL WINAPI DetouredEnumDisplaySettingsW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode)
{
  // Call the real EnumDisplaySettingsW function
  BOOL devModePopulated = WindowsEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);

  #if defined(VERBOSE_TEST_VERSION)
  // Show message
  std::wstring message = std::format(L"Detoured EnumDisplaySettingsW function called with the following parameters:\n"
    "\nlpszDeviceName = {}\niModeNum = ", lpszDeviceName);
  if (iModeNum == ENUM_CURRENT_SETTINGS)
    message += L"ENUM_CURRENT_SETTINGS";
  else if (iModeNum == ENUM_REGISTRY_SETTINGS)
    message += L"ENUM_REGISTRY_SETTINGS";
  else
    message += std::format(L"{:d}", iModeNum);
  MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
  #endif

  // Spoof the resolution
  BOOL resolutionSpoofed = SpoofEDSResolution(devModePopulated, lpszDeviceName, iModeNum, &lpDevMode->dmFields,
    &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency,
    &lpDevMode->dmDisplayFlags, NULL, NULL);

  return devModePopulated || resolutionSpoofed;
}

// DetouredEnumDisplaySettingsExA function
BOOL WINAPI DetouredEnumDisplaySettingsExA(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode, DWORD dwFlags)
{
  // Call the real EnumDisplaySettingsExA function
  BOOL devModePopulated = WindowsEnumDisplaySettingsExA(lpszDeviceName, iModeNum, lpDevMode, dwFlags);

  // Convert the device name to a wide character string
  uint16_t deviceNameLength = MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, NULL, 0);
  std::wstring deviceName(deviceNameLength, 0);
  MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, &deviceName[0], deviceNameLength);
  deviceName.pop_back();

  #if defined(VERBOSE_TEST_VERSION)
  // Show message
  std::wstring message = std::format(L"Detoured EnumDisplaySettingsExA function called with the following parameters:\n"
    "\nlpszDeviceName = {}\niModeNum = ", deviceName);
  if (iModeNum == ENUM_CURRENT_SETTINGS)
    message += L"ENUM_CURRENT_SETTINGS";
  else if (iModeNum == ENUM_REGISTRY_SETTINGS)
    message += L"ENUM_REGISTRY_SETTINGS";
  else
    message += std::format(L"{:d}", iModeNum);
  MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
  #endif

  // Spoof the resolution
  BOOL resolutionSpoofed = SpoofEDSResolution(devModePopulated, deviceName.c_str(), iModeNum, &lpDevMode->dmFields,
    &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency,
    &lpDevMode->dmDisplayFlags, &lpDevMode->dmPosition, &lpDevMode->dmDisplayOrientation);

  return devModePopulated || resolutionSpoofed;
}

// DetouredEnumDisplaySettingsExW function
BOOL WINAPI DetouredEnumDisplaySettingsExW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode, DWORD dwFlags)
{
  // Call the real EnumDisplaySettingsExW function
  BOOL devModePopulated = WindowsEnumDisplaySettingsExW(lpszDeviceName, iModeNum, lpDevMode, dwFlags);

  #if defined(VERBOSE_TEST_VERSION)
  // Show message
  std::wstring message = std::format(L"Detoured EnumDisplaySettingsExW function called with the following parameters:\n"
    "\nlpszDeviceName = {}\niModeNum = ", lpszDeviceName);
  if (iModeNum == ENUM_CURRENT_SETTINGS)
    message += L"ENUM_CURRENT_SETTINGS";
  else if (iModeNum == ENUM_REGISTRY_SETTINGS)
    message += L"ENUM_REGISTRY_SETTINGS";
  else
    message += std::format(L"{:d}", iModeNum);
  MessageBox(NULL, message.c_str(), L"Spoof Resolution", MB_OK);
  #endif

  // Spoof the resolution
  BOOL resolutionSpoofed = SpoofEDSResolution(devModePopulated, lpszDeviceName, iModeNum, &lpDevMode->dmFields,
    &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency,
    &lpDevMode->dmDisplayFlags, &lpDevMode->dmPosition, &lpDevMode->dmDisplayOrientation);

  return devModePopulated || resolutionSpoofed;
}

// DllMain function
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  #if not defined(VERSOIN_DLL_VERSION) && not defined (WINHTTP_DLL_VERSION)
  // Restore the in memory import table after we are loaded by withdll.exe
  DetourRestoreAfterWith();
  #endif

  // Switch based on the reason for this function call
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
    #if defined(TEST_VERSION) || defined(VERBOSE_TEST_VERSION)
    // Show message
    MessageBox(NULL, L"DllMain function called with the following parameters:\n\n"
      "ul_reason_for_call = DLL_PROCESS_ATTACH", L"Spoof Resolution", MB_OK);
    #endif

    // Save the module handle for later use
    gModule = hModule;

    // Attach the function detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)WindowsGetDeviceCaps, DetouredGetDeviceCaps);
    DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsA, DetouredEnumDisplaySettingsA);
    DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsW, DetouredEnumDisplaySettingsW);
    DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsExA, DetouredEnumDisplaySettingsExA);
    DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsExW, DetouredEnumDisplaySettingsExW);
    DetourTransactionCommit();

    break;
  case DLL_PROCESS_DETACH:
    #if defined(VERBOSE_TEST_VERSION)
    // Show message
    MessageBox(NULL, L"DllMain function called with the following parameters:\n\n"
      "ul_reason_for_call = DLL_PROCESS_DETACH", L"Spoof Resolution", MB_OK);
    #endif

    // Detach the function detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)WindowsGetDeviceCaps, DetouredGetDeviceCaps);
    DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsA, DetouredEnumDisplaySettingsA);
    DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsW, DetouredEnumDisplaySettingsW);
    DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsExA, DetouredEnumDisplaySettingsExA);
    DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsExW, DetouredEnumDisplaySettingsExW);
    DetourTransactionCommit();

    break;
  }

  return TRUE;
}