# Spoof Resolution

A DLL based approach to spoofing the resolution information that an application or game receives from various Windows API calls.  Currently the following API functions are detoured to provide spoofed resolution information to applications or games:

- GetSystemMetrics
- GetDeviceCaps
- EnumDisplaySettingsA
- EnumDisplaySettingsW
- EnumDisplaySettingsExA
- EnumDisplaySettingsExW

To spoof the resolution for an application or game, place the `withdll.exe` and `spoofres.dll` files in the application or game folder and create a `spoofres.ini` file in the same folder with the following format:

```
; All sections and keys are optional

; This section controls logging
; If Logging key is set to On/Yes/True and no LogFile key is found, Spoof Resolution will create a log file in the same
;   folder as the Spoof Resolution DLL file
[SpoofResolution]
Logging = On
LogFile = C:\Path\To\LogFile.log

; This section contains information used when spoofing resolution via the GetSystemMetrics Windows API function
[GSM]
Width = 3840
Height = 2160

; This section contains information used when spoofing resolution via the GetDeviceCaps Windows API function
[GDC]
Width = 3840
Height = 2160
BitsPerPixel = 32
Frequency = 60

; This section contains information used when spoofing resolution via the EnumDisplaySettings Windows API functions and
;   can be present multiple times
; Device is the device that the application/game is inquiring about and can be a full device name or a * wildcard
; Mode is the mode number for the device that the application/game is inquiring about and can be any number starting at
;   0, the word Current to represent the current resolution (Windows API ENUM_CURRENT_SETTINGS equivalent), the word
;   Registry to represent the resolution information stored in the registry (Windows API ENUM_REGISTRY_SETTINGS
;   equivalent), or a * wildcard
[EDS|Device|Mode]
Width = 3840
Height = 2160
BitsPerPixel = 32
Frequency = 60
Flags = 0
PositionX = 0
PositionY = 0
Orientation = 0
```

For example, this `spoofres.ini` file would spoof the width and height for all calls to all of the above Windows API functions:

```
[GSM]
Width = 3840
Height = 2160

[GDC]
Width = 3840
Height = 2160

[EDS|*|*]
Width = 3840
Height = 2160
```

and this `spoofres.ini` file would spoof the width and height and frequency (ie: refresh rate) for all calls to the EnumDisplaySetting API functions that request resolution information about the first monitor's current resolution:

```
[EDS|\\.\DISPLAY1|Current]
Width = 3840
Height = 2160
Frequency = 60
```

Then start the application or game using the included `withdll.exe` utility via the following command:

```
withdll.exe /d:spoofres.dll program.exe
```

or for applications or games that load either the Windows `version.dll` or `winhttp.dll` files you can place the `version.dll` or `winhttp.dll` file in the application or game folder, instead of the `withdll.exe` and `spoofres.dll` files, and start the application or game as you normally would.  The application or game will load the `version.dll` or `winhttp.dll` file which will provide the resolution spoofing functionality and will proxy any calls to the Windows `version.dll` or `winhttp.dll` files.

Note: since it is normal for various anti-virus programs to flag the `withdll.exe` file as a virus (since this utility can be also used for nefarious purposes) it is packaged inside of a zip file to prevent immediate anti-virus program action.