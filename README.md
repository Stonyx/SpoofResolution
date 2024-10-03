# Spoof Resolution

A DLL based approach to spoofing the resolution information that an application or game receives from various Windows API calls.  Currently the following 4 API functions are detoured to provide spoofed resolution information to applications or games:

- EnumDisplaySettingsA
- EnumDisplaySettingsW
- EnumDisplaySettingsExA
- EnumDisplaySettingsExW

These represent the low level functions that applications and games use to retrive resolution information.  In the future higher level functions will hopefully be added to support more applications and games.

To spoof the resolution for an application or game, place the `withdll.exe` and `spoofres.dll` files in the application or game folder and create a `spoofres.ini` file in the same folder with the following format:

```
[Device|Mode]
Width = 1920
Height = 1080
BitsPerPixel = 32
Frequency = 60
Flags = 0
PositionX = 0
PositionY = 0
Orientation = 0
```

where `Device` is the device that the application or game is inquiring about and can be a full case sensitive name or a `*` wildcard and where `Mode` is the mode number for the device that the application or game is inquiring about and can be any number starting at `0`, the word `Current` to represent the current resolution (Windows API `ENUM_CURRENT_SETTINGS` equivalent), the word `Registry` to represent the resolution information stored in the registry (Windows API `ENUM_REGISTRY_SETTINGS` equivalent), or a `*` wildcard.

For example this sample `spoofres.ini` file would spoof the width and height for all calls to any of the above Windows API functions:

```
[*|*]
Width = 1920
Height = 1080
```

and this sample `spoofres.ini` file would spoof the width and height and frequency (ie: refresh rate) for any calls to the above Windows API functions that request resolution information about the first monitor's current resolution:

```
[\\.\DISPLAY1|Current]
Width = 1920
Height = 1080
Frequency = 60
```

Then start the application or game using the included `withdll.exe` utility via the following command:

```
withdll.exe /d:spoofres.dll program.exe
```

or for applications or games that load either the Windows `version.dll` or `winhttp.dll` files you can place the `version.dll` or `winhttp.dll` file in the application or game folder, instead of the `withdll.exe` and `spoofres.dll` files, and start the application or game as you normally would.  The application or game will load the `version.dll` or `winhttp.dll` file which will provide the resolution spoofing functionality and will proxy any calls to the Windows `version.dll` or `winhttp.dll` files.
