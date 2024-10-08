#include <filesystem>
#include <fstream>
#include <windows.h>
#if defined(VERSION_DLL_VERSION) || defined(WINHTTP_DLL_VERSION)
#include <QuickDllProxy/DllProxy.h>
#endif
#include <Detours/detours.h>
#include <SimpleIni/SimpleIni.h>

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
static int(WINAPI* WindowsGetSystemMetrics)(int nIndex) = GetSystemMetrics;
static int(WINAPI* WindowsGetDeviceCaps)(HDC hdc, int index) = GetDeviceCaps;
static BOOL(WINAPI* WindowsEnumDisplaySettingsA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode) =
  EnumDisplaySettingsA;
static BOOL(WINAPI* WindowsEnumDisplaySettingsW)(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode) =
  EnumDisplaySettingsW;
static BOOL(WINAPI* WindowsEnumDisplaySettingsExA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode,
  DWORD dwFlags) = EnumDisplaySettingsExA;
static BOOL(WINAPI* WindowsEnumDisplaySettingsExW)(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode,
  DWORD dwFlags) = EnumDisplaySettingsExW;
struct {
  bool GetSystemMetrics : 1 = false;
  bool GetDeviceCaps : 1 = false;
  bool EnumDisplaySettingsA : 1 = false;
  bool EnumDisplaySettingsW : 1 = false;
  bool EnumDisplaySettingsExA : 1 = false;
  bool EnumDisplaySettingsExW : 1 = false;
} gDetouredFunctions;
std::unique_ptr<CSimpleIni> gIniFile = std::unique_ptr<CSimpleIni>(nullptr);
std::shared_ptr<std::wofstream> gLogFile = std::shared_ptr<std::wofstream>(nullptr);

// GetIniFile function
static void LoadIniFile(HMODULE module)
{
  // Get the full path to this DLL
  std::wstring path(MAX_PATH, 0);
  if (GetModuleFileName(module, &path[0], MAX_PATH) == 0)
  {
    // Show an error message
    MessageBox(NULL, L"Failed to get path to Spoof Resolution DLL file", L"Spoof Resolution", MB_OK | MB_ICONERROR);

    return;
  }

  // Remove the file name from the path and replace it with spoofres.ini
  path.erase(path.rfind(std::filesystem::path::preferred_separator) + 1);
  path += L"spoofres.ini";

  // Check if the ini file does not exist
  if (!std::filesystem::exists(path))
  {
    // Show an error message
    MessageBox(NULL, L"Failed to locate spoofres.ini file", L"Spoof Resolution", MB_OK | MB_ICONERROR);

    return;
  }

  // Open the ini file
  gIniFile = std::make_unique<CSimpleIni>();
  gIniFile->SetUnicode();
  if (gIniFile->LoadFile(path.c_str()) < 0)
  {
    // Show an error message and reset the ini file pointer
    // Note: std::format adds a significant amount of additional code into the DLL so instead we are using stdio
    //   functions to compose the messages
    wchar_t message[256];
    swprintf_s(message, L"Failed to open %s file", path.c_str());
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return;
  }
}

// LoadLogFile function
static void LoadLogFile(HMODULE module)
{
  // Check if we do not have a valid ini file
  if (gIniFile == nullptr)
    return;

  // Check if we do not have a logging key in the ini file
  if (!gIniFile->KeyExists(L"SpoofResolution", L"Logging"))
    return;

  // Check if the logging key is not set to On, Yes, or True using case insensitive comparisons
  std::wstring logging = gIniFile->GetValue(L"SpoofResolution", L"Logging");
  if (!std::ranges::equal(logging, std::wstring(L"On"),
      [](const WCHAR a, const WCHAR b) { return std::tolower(a) == std::tolower(b); }) &&
      !std::ranges::equal(logging, std::wstring(L"Yes"),
      [](const WCHAR a, const WCHAR b) { return std::tolower(a) == std::tolower(b); }) &&
      !std::ranges::equal(logging, std::wstring(L"True"),
      [](const WCHAR a, const WCHAR b) { return std::tolower(a) == std::tolower(b); }))
    return;

  // Check if we have a LogFile key in the ini file and load the log file path otherwise use the DLL file path as the
  //   log file path base
  std::wstring path;
  if (gIniFile->KeyExists(L"SpoofResolution", L"LogFile"))
  {
    path = gIniFile->GetValue(L"SpoofResolution", L"LogFile");
  }  
  else
  {
    // Get the full path to this DLL
    path = std::wstring(MAX_PATH, 0);
    if (GetModuleFileName(module, &path[0], MAX_PATH) == 0)
    {
      // Show an error message
      MessageBox(NULL, L"Failed to get path to Spoof Resolution DLL file", L"Spoof Resolution", MB_OK | MB_ICONERROR);

      return;
    }

    // Remove the file name from the path and replace it with spoofres.log
    path.erase(path.rfind(std::filesystem::path::preferred_separator) + 1);
    path += L"spoofres.log";
  }

  // Open the log file
  gLogFile = std::make_unique<std::wofstream>(path, std::wofstream::out);
  if (!*gLogFile)
  {
    // Show an error message and reset the log file pointer
    // Note: std::format adds a significant amount of additional code into the DLL so instead we are using stdio
    //   functions to compose the messages
    wchar_t message[256];
    swprintf_s(message, L"Failed to open %s file", path.c_str());
    MessageBox(NULL, message, L"Spoof Resolution", MB_OK | MB_ICONERROR);
    gLogFile.reset();

    return;
  }

  // Enable UTF-8 support
  gLogFile->imbue(std::locale(std::locale::empty(), new std::codecvt_byname<wchar_t, char, mbstate_t>("en_US.UTF-8")));
}

// SpoofGSMResolution function
int SpoofGSMResolution(int realFuncRetValue, int index)
{
  // Check if we do not have a valid ini file
  if (gIniFile == nullptr)
    return realFuncRetValue;

  // Load the resolution information from the ini file
  // Note: we load all of the reolution information from the ini file before assigning any of it to the passed in
  //   pointers to avoid partially spoofing the resolution information if an exception is thrown during loading
  std::unique_ptr<int> spoofedValue = std::unique_ptr<int>(nullptr);
  try
  {
    if (index == SM_CXSCREEN && gIniFile->KeyExists(L"GSM", L"Width"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GSM", L"Width")));
    else if (index == SM_CYSCREEN && gIniFile->KeyExists(L"GSM", L"Height"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GSM", L"Height")));
  }
  catch (std::invalid_argument)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }
  catch (std::out_of_range)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }

  // Check if we do not have a spoofed value
  if (spoofedValue == nullptr)
    return realFuncRetValue;

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Spoofed GetSystemMetrics resolution for index ";
    if (index == SM_CXSCREEN)
      *gLogFile << L"SM_CXSCREEN with the following details: Width = " << *spoofedValue << "\n";
    else if (index == SM_CYSCREEN)
      *gLogFile << L"SM_CYSCREEN with the following details: Height = " << *spoofedValue << "\n";
  }

  return *spoofedValue;
}

// DetouredGetSystemMetrics function
int WINAPI DetouredGetSystemMetrics(int nIndex)
{
  // Call the real GetSystemMetrics function
  int value = WindowsGetSystemMetrics(nIndex);

  // Write to the log file
  if (gLogFile != nullptr)
    *gLogFile << L"Detoured GetSystemMetrics function called with the following parameters: nIndex = " << nIndex <<
      "\n";

  // Spoof the resolution
  value = SpoofGSMResolution(value, nIndex);

  return value;
}

// SpoofGDCResolution function
int SpoofGDCResolution(int realFuncRetValue, int index)
{
  // Check if we do not have a valid ini file
  if (gIniFile == nullptr)
    return realFuncRetValue;

  // Load the resolution information from the ini file
  // Note: we load all of the reolution information from the ini file before assigning any of it to the passed in
  //   pointers to avoid partially spoofing the resolution information if an exception is thrown during loading
  std::unique_ptr<int> spoofedValue = std::unique_ptr<int>(nullptr);
  try
  {
    if (index == HORZRES && gIniFile->KeyExists(L"GDC", L"Width"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GDC", L"Width")));
    else if (index == VERTRES && gIniFile->KeyExists(L"GDC", L"Height"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GDC", L"Height")));
    else if (index == BITSPIXEL && gIniFile->KeyExists(L"GDC", L"BitsPerPixel"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GDC", L"BitsPerPixel")));
    else if (index == VREFRESH && gIniFile->KeyExists(L"GDC", L"Frequency"))
      spoofedValue = std::make_unique<int>(std::stoi(gIniFile->GetValue(L"GDC", L"Frequency")));
  }
  catch (std::invalid_argument)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }
  catch (std::out_of_range)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }

  // Check if we do not have a spoofed value
  if (spoofedValue == nullptr)
    return realFuncRetValue;

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Spoofed GetDeviceCaps resolution for index ";
    if (index == HORZRES)
      *gLogFile << L"HORZRES with the following details: Width = " << *spoofedValue << "\n";
    else if (index == VERTRES)
      *gLogFile << L"VERTRES with the following details: Height = " << *spoofedValue << "\n";
    else if (index == BITSPIXEL)
      *gLogFile << L"BITSPIXEL with the following details: Bits Per Pixel = " << *spoofedValue << "\n";
    else if (index == VREFRESH)
      *gLogFile << L"VREFRESH with the following details: Frequency = " << *spoofedValue << "\n";
  }  

  return *spoofedValue;
}

// DetouredGetDeviceCaps function
int WINAPI DetouredGetDeviceCaps(HDC hdc, int index)
{
  // Call the real GetDeviceCaps function
  int value = WindowsGetDeviceCaps(hdc, index);

  // Write to the log file
  if (gLogFile != nullptr)
    *gLogFile << L"Detoured GetDeviceCaps function called with the following parameters: index = " << index << "\n";

  // Spoof the resolution
  value = SpoofGDCResolution(value, index);

  return value;
}

// SpoofEDSResolution function
BOOL SpoofEDSResolution(BOOL realFuncRetValue, LPCWSTR deviceName, DWORD modeNumber, DWORD* fields, DWORD* width,
  DWORD* height, DWORD* bitsPerPixel, DWORD* frequency, DWORD* flags, POINTL* position, DWORD* orientation)
{
  // Check if we do not have a valid ini file
  if (gIniFile == nullptr)
    return realFuncRetValue;

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
    // Figure out the matching sections
    std::vector<std::wstring> sections;
    if (modeNumber == ENUM_CURRENT_SETTINGS)
    {
      if (deviceName != NULL)
        sections.push_back(std::wstring(L"EDS|") + deviceName + std::wstring(L"|Current"));
      else
        sections.push_back(std::wstring(L"EDS|NULL|Current"));
      sections.push_back(std::wstring(L"EDS|*|Current"));
    }
    else if (modeNumber == ENUM_REGISTRY_SETTINGS)
    {
      if (deviceName != NULL)
        sections.push_back(std::wstring(L"EDS|") + deviceName + std::wstring(L"|Registry"));
      else
        sections.push_back(std::wstring(L"EDS|NULL|Registry"));
      sections.push_back(std::wstring(L"EDS|*|Registry"));
    }
    else
    {
      if (deviceName != NULL)
        sections.push_back(std::wstring(L"EDS|") + deviceName + std::wstring(L"|") + std::to_wstring(modeNumber));
      else
        sections.push_back(std::wstring(L"EDS|NULL|") + std::to_wstring(modeNumber));
      sections.push_back(std::wstring(L"EDS|*|") + std::to_wstring(modeNumber));
    }
    if (realFuncRetValue)
    {
      if (deviceName != NULL)
        sections.push_back(std::wstring(L"EDS|") + deviceName + std::wstring(L"|*"));
      else
        sections.push_back(std::wstring(L"EDS|NULL|*"));
      sections.push_back(std::wstring(L"EDS|*|*"));
    }

    // Loop through the matching sections
    for (std::wstring section : sections)
    {
      // Check if this section exists
      if (gIniFile->SectionExists(section.c_str()))
      {
        // Check if the passed in pointers are valid and if the keys exist and load the resolution information
        if (width != NULL && gIniFile->KeyExists(section.c_str(), L"Width"))
          spoofedWidth = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(), L"Width")));
        if (height != NULL && gIniFile->KeyExists(section.c_str(), L"Height"))
          spoofedHeight = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(), L"Height")));
        if (bitsPerPixel != NULL && gIniFile->KeyExists(section.c_str(), L"BitsPerPixel"))
          spoofedBitsPerPixel = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(),
            L"BitsPerPixel")));
        if (frequency != NULL && gIniFile->KeyExists(section.c_str(), L"Frequency"))
          spoofedFrequency = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(), L"Frequency")));
        if (flags != NULL && gIniFile->KeyExists(section.c_str(), L"Flags"))
          spoofedFlags = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(), L"Flags")));
        if (position != NULL && gIniFile->KeyExists(section.c_str(), L"PositionX") &&
            gIniFile->KeyExists(section.c_str(), L"PositionY"))
        {
          spoofedPosition = std::make_unique<POINTL>();
          spoofedPosition->x = std::stoul(gIniFile->GetValue(section.c_str(), L"PositionX"));
          spoofedPosition->y = std::stoul(gIniFile->GetValue(section.c_str(), L"PositionY"));
        }
        if (orientation != NULL && gIniFile->KeyExists(section.c_str(), L"Orientation"))
          spoofedOrientation = std::make_unique<DWORD>(std::stoul(gIniFile->GetValue(section.c_str(), L"Orientation")));

        // Stop looping
        break;
      }
    }
  }
  catch (std::invalid_argument)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }
  catch (std::out_of_range)
  {
    // Show an error message and reset the ini file pointer
    MessageBox(NULL, L"Failed to load resolution information from spoofres.ini file", L"Spoof Resolution",
      MB_OK | MB_ICONERROR);
    gIniFile.reset();

    return realFuncRetValue;
  }

  // Check if we do not have any spoofed values
  if (spoofedWidth == nullptr && spoofedHeight == nullptr && spoofedBitsPerPixel == nullptr &&
      spoofedFrequency == nullptr && spoofedFlags == nullptr && spoofedPosition == nullptr &&
      spoofedOrientation == nullptr)
    return realFuncRetValue;

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Spoofed EnumDisplaySettings resolution for device ";
    if (deviceName == NULL)
      *gLogFile << L"NULL and mode number ";
    else
      *gLogFile << deviceName << L" and mode number ";
    if (modeNumber == ENUM_CURRENT_SETTINGS)
      *gLogFile << L"ENUM_CURRENT_SETTINGS with the following details: ";
    else if (modeNumber == ENUM_REGISTRY_SETTINGS)
      *gLogFile << L"ENUM_REGISTRY_SETTINGS with the following details: ";
    else
      *gLogFile << modeNumber << L" with the following details: ";
    if (spoofedWidth != nullptr)
      *gLogFile << L"Width = " << *spoofedWidth;
    if (spoofedWidth != nullptr && (spoofedHeight != nullptr || spoofedBitsPerPixel != nullptr ||
        spoofedFrequency != nullptr || spoofedFlags != nullptr || spoofedPosition != nullptr ||
        spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedHeight != nullptr)
      *gLogFile << L"Height = " << *spoofedHeight;
    if ((spoofedWidth != nullptr || spoofedHeight != nullptr) && (spoofedBitsPerPixel != nullptr ||
        spoofedFrequency != nullptr || spoofedFlags != nullptr || spoofedPosition != nullptr ||
        spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedBitsPerPixel != nullptr)
      *gLogFile << L"Bits Per Pixel = " << *spoofedBitsPerPixel;
    if ((spoofedWidth != nullptr || spoofedHeight != nullptr || spoofedBitsPerPixel != nullptr) &&
        (spoofedFrequency != nullptr || spoofedFlags != nullptr || spoofedPosition != nullptr ||
        spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedFrequency != nullptr)
      *gLogFile << L"Frequency = " << *spoofedFrequency;
    if ((spoofedWidth != nullptr || spoofedHeight != nullptr || spoofedBitsPerPixel != nullptr ||
        spoofedFrequency != nullptr) && (spoofedFlags != nullptr || spoofedPosition != nullptr ||
        spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedFlags != nullptr)
      *gLogFile << L"Flags = " << *spoofedFlags;
    if ((spoofedWidth != nullptr || spoofedHeight != nullptr || spoofedBitsPerPixel != nullptr ||
        spoofedFrequency != nullptr || spoofedFlags != nullptr) && (spoofedPosition != nullptr ||
        spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedPosition != nullptr)
      *gLogFile << L"Position X = " << spoofedPosition->x << ", Position Y = " << spoofedPosition->y;
    if ((spoofedWidth != nullptr || spoofedHeight != nullptr || spoofedBitsPerPixel != nullptr ||
        spoofedFrequency != nullptr || spoofedFlags != nullptr || spoofedPosition != nullptr) &&
        (spoofedOrientation != nullptr))
      *gLogFile << L", ";
    if (spoofedOrientation != nullptr)
      *gLogFile << L"\nOrientation = " << *spoofedOrientation;
    *gLogFile << "\n";
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

  return TRUE;
}

// DetouredEnumDisplaySettingsA function
BOOL WINAPI DetouredEnumDisplaySettingsA(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode)
{
  // Call the real EnumDisplaySettingsA function
  BOOL success = WindowsEnumDisplaySettingsA(lpszDeviceName, iModeNum, lpDevMode);

  // Convert the device name to a wide character string
  std::unique_ptr<std::wstring> deviceName = std::unique_ptr<std::wstring>(nullptr);
  if (lpszDeviceName != NULL)
  {
    uint16_t deviceNameLength = MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, NULL, 0);
    deviceName = std::make_unique<std::wstring>(deviceNameLength, 0);
    MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, &(*deviceName)[0], deviceNameLength);
    deviceName->pop_back();
  }

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Detoured EnumDisplaySettingsA function called with the following parameters: lpszDeviceName = ";
    if (deviceName == nullptr)
      *gLogFile << "NULL, iModeNum = ";
    else
      *gLogFile << *deviceName << L", iModeNum = ";
    if (iModeNum == ENUM_CURRENT_SETTINGS)
      *gLogFile << L"ENUM_CURRENT_SETTINGS\n";
    else if (iModeNum == ENUM_REGISTRY_SETTINGS)
      *gLogFile << L"ENUM_REGISTRY_SETTINGS\n";
    else
      *gLogFile << iModeNum << "\n";
  }

  // Spoof the resolution
  success = SpoofEDSResolution(success, (deviceName != nullptr ? deviceName->c_str() : NULL), iModeNum,
    &lpDevMode->dmFields, &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel,
    &lpDevMode->dmDisplayFrequency, &lpDevMode->dmDisplayFlags, NULL, NULL);

  return success;
}

// DetouredEnumDisplaySettingsW function
BOOL WINAPI DetouredEnumDisplaySettingsW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode)
{
  // Call the real EnumDisplaySettingsW function
  BOOL success = WindowsEnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Detoured EnumDisplaySettingsW function called with the following parameters: lpszDeviceName = ";
    if (lpszDeviceName == NULL)
      *gLogFile << L"NULL, iModeNum = ";
    else
      *gLogFile << lpszDeviceName << L", iModeNum = ";
    if (iModeNum == ENUM_CURRENT_SETTINGS)
      *gLogFile << L"ENUM_CURRENT_SETTINGS\n";
    else if (iModeNum == ENUM_REGISTRY_SETTINGS)
      *gLogFile << L"ENUM_REGISTRY_SETTINGS\n";
    else
      *gLogFile << iModeNum << "\n";
  }

  // Spoof the resolution
  success = SpoofEDSResolution(success, lpszDeviceName, iModeNum, &lpDevMode->dmFields, &lpDevMode->dmPelsWidth,
    &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency, &lpDevMode->dmDisplayFlags,
    NULL, NULL);

  return success;
}

// DetouredEnumDisplaySettingsExA function
BOOL WINAPI DetouredEnumDisplaySettingsExA(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA* lpDevMode, DWORD dwFlags)
{
  // Call the real EnumDisplaySettingsExA function
  BOOL success = WindowsEnumDisplaySettingsExA(lpszDeviceName, iModeNum, lpDevMode, dwFlags);

  // Convert the device name to a wide character string
  std::unique_ptr<std::wstring> deviceName = std::unique_ptr<std::wstring>(nullptr);
  if (lpszDeviceName != NULL)
  {
    uint16_t deviceNameLength = MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, NULL, 0);
    deviceName = std::make_unique<std::wstring>(deviceNameLength, 0);
    MultiByteToWideChar(CP_ACP, 0, lpszDeviceName, -1, &(*deviceName)[0], deviceNameLength);
    deviceName->pop_back();
  }

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Detoured EnumDisplaySettingsExA function called with the following parameters: lpszDeviceName = ";
    if (deviceName == nullptr)
      *gLogFile << L"NULL, iModeNum = ";
    else
      *gLogFile << *deviceName << L", iModeNum = ";
    if (iModeNum == ENUM_CURRENT_SETTINGS)
      *gLogFile << L"ENUM_CURRENT_SETTINGS\n";
    else if (iModeNum == ENUM_REGISTRY_SETTINGS)
      *gLogFile << L"ENUM_REGISTRY_SETTINGS\n";
    else
      *gLogFile << iModeNum << "\n";
  }

  // Spoof the resolution
  success = SpoofEDSResolution(success, (deviceName != nullptr ? deviceName->c_str() : NULL), iModeNum,
    &lpDevMode->dmFields, &lpDevMode->dmPelsWidth, &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel,
    &lpDevMode->dmDisplayFrequency, &lpDevMode->dmDisplayFlags, &lpDevMode->dmPosition,
    &lpDevMode->dmDisplayOrientation);

  return success;
}

// DetouredEnumDisplaySettingsExW function
BOOL WINAPI DetouredEnumDisplaySettingsExW(LPCWSTR lpszDeviceName, DWORD iModeNum, DEVMODEW* lpDevMode, DWORD dwFlags)
{
  // Call the real EnumDisplaySettingsExW function
  BOOL success = WindowsEnumDisplaySettingsExW(lpszDeviceName, iModeNum, lpDevMode, dwFlags);

  // Write to the log file
  if (gLogFile != nullptr)
  {
    *gLogFile << L"Detoured EnumDisplaySettingsExW function called with the following parameters: lpszDeviceName = " <<
      lpszDeviceName << L", iModeNum = ";
    if (iModeNum == ENUM_CURRENT_SETTINGS)
      *gLogFile << L"ENUM_CURRENT_SETTINGS\n";
    else if (iModeNum == ENUM_REGISTRY_SETTINGS)
      *gLogFile << L"ENUM_REGISTRY_SETTINGS\n";
    else
      *gLogFile << iModeNum << "\n";
  }

  // Spoof the resolution
  success = SpoofEDSResolution(success, lpszDeviceName, iModeNum, &lpDevMode->dmFields, &lpDevMode->dmPelsWidth,
    &lpDevMode->dmPelsHeight, &lpDevMode->dmBitsPerPel, &lpDevMode->dmDisplayFrequency, &lpDevMode->dmDisplayFlags,
    &lpDevMode->dmPosition, &lpDevMode->dmDisplayOrientation);

  return success;
}

// DllMain function
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  // Switch based on the reason for this function call
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
    #if not defined(VERSOIN_DLL_VERSION) && not defined (WINHTTP_DLL_VERSION)
    // Restore the in memory import table after we are loaded by withdll.exe
    DetourRestoreAfterWith();
    #endif

    // Load the ini file
    LoadIniFile(hModule);

    // Load the log file
    LoadLogFile(hModule);

    // Write to the log file
    if (gLogFile != nullptr)
      *gLogFile << L"DllMain function called with the following parameters: ul_reason_for_call = DLL_PROCESS_ATTACH\n";

    // Check if we have a valid ini file
    if (gIniFile != nullptr)
    {
      // Start the detour process
      DetourTransactionBegin();
      DetourUpdateThread(GetCurrentThread());

      // Check if there is a GSM section in the ini file
      if (gIniFile->SectionExists(L"GSM"))
      {
        // Detour the GetSystemMetrics function
        DetourAttach(&(PVOID&)WindowsGetSystemMetrics, DetouredGetSystemMetrics);
        gDetouredFunctions.GetSystemMetrics = true;

        // Write to the log file
        if (gLogFile != nullptr)
          *gLogFile << L"Detouring GetSystemMetrics function\n";
      }

      // Check if there is a GDC section in the ini file
      if (gIniFile->SectionExists(L"GDC"))
      {
        // Detour the GetDeviceCaps function
        DetourAttach(&(PVOID&)WindowsGetDeviceCaps, DetouredGetDeviceCaps);
        gDetouredFunctions.GetDeviceCaps = true;

        // Write to the log file
        if (gLogFile != nullptr)
          *gLogFile << L"Detouring GetDeviceCaps function\n";
      }

      // Check if there are any EDS sections in the ini file
      std::list<CSimpleIni::Entry> sections;
      gIniFile->GetAllSections(sections);
      if (std::find_if(sections.begin(), sections.end(),
          [&](CSimpleIni::Entry& entry) { return std::wstring(entry.pItem).starts_with(L"EDS"); }) != sections.end())
      {
        // Detour the EnumDisplaySettings functions
        DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsA, DetouredEnumDisplaySettingsA);
        gDetouredFunctions.EnumDisplaySettingsA = true;
        DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsW, DetouredEnumDisplaySettingsW);
        gDetouredFunctions.EnumDisplaySettingsW = true;
        DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsExA, DetouredEnumDisplaySettingsExA);
        gDetouredFunctions.EnumDisplaySettingsExA = true;
        DetourAttach(&(PVOID&)WindowsEnumDisplaySettingsExW, DetouredEnumDisplaySettingsExW);
        gDetouredFunctions.EnumDisplaySettingsExW = true;

        // Write to the log file
        if (gLogFile != nullptr)
          *gLogFile << L"Detouring EnumDisplaySettings functions\n";
      }

      // Finish the detour process
      DetourTransactionCommit();
    }

    break;
  case DLL_PROCESS_DETACH:
    // Write to the log file
    if (gLogFile != nullptr)
      *gLogFile << L"DllMain function called with the following parameters: ul_reason_for_call = DLL_PROCESS_DETACH\n";

    // Close the log file
    if (gLogFile != nullptr)
      gLogFile->close();

    // Detach the function detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    if (gDetouredFunctions.GetSystemMetrics)
      DetourDetach(&(PVOID&)WindowsGetSystemMetrics, DetouredGetSystemMetrics);
    if (gDetouredFunctions.GetDeviceCaps)
      DetourDetach(&(PVOID&)WindowsGetDeviceCaps, DetouredGetDeviceCaps);
    if (gDetouredFunctions.EnumDisplaySettingsA)
      DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsA, DetouredEnumDisplaySettingsA);
    if (gDetouredFunctions.EnumDisplaySettingsW)
      DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsW, DetouredEnumDisplaySettingsW);
    if (gDetouredFunctions.EnumDisplaySettingsExA)
      DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsExA, DetouredEnumDisplaySettingsExA);
    if (gDetouredFunctions.EnumDisplaySettingsExW)
      DetourDetach(&(PVOID&)WindowsEnumDisplaySettingsExW, DetouredEnumDisplaySettingsExW);
    DetourTransactionCommit();

    break;
  }

  return TRUE;
}