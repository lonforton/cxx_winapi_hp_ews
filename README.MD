# C++ Winapi wrapper for HP EWS connection

**Input:** printer's vid and pid

**Output:** printer full response or printer status

Winapi wrapper to connect to embedded web server in HP printers (HP EWS) via usb and get device current status. Async read and write modes. 

For the start you only need to know only vid and pid of the device. If you need to set security, call ```CxxWinapi::set_security``` before calling ```CxxWinapi::get_winusb_handle``` or ```CxxWinapi::get_file_interface_handle``` function.

If winusb handle wasn't found, it's either printer disconnected or there's no possibility to use winusb interface, you should call ```CxxWinapi::get_file_interface_handle``` to obtain file interface and use it with corresponding function.

By default standard out package will be used to get printer response, but you can specify your own package, just don't forget about new line control character.

Printer responsed as html page inside xml packet which contains status inside "deviceStatus_tableCell" tag. You can call ```CxxWinapi::get_text_status_from_html``` to get only status string.



## Defining GUIDs and device IDs

It's possible to use your our GUIDs and IDs, check insides of CxxWinapi::get_winusb_handle or CxxWinapi::get_file_interface_handle

There are two ways to define Device Interface Guid

```
// example  GUID_DEVINTERFACE_DISK {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
DEFINE_GUID(GUID_DEVINTERFACE_DISK, 0x53f56307, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);
static constexpr GUID GUID_DEVINTERFACE_DISK = {0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};
```

Define GUID 

```
GUID* right_guid = (GUID*)(void*)&GUID_DEVINTERFACE_DISK;
```

Define device instance identifier

```
WCHAR DeviceInstanceID[] = L"USB\\VID_03F0&PID_612A&MI_01\\6&2EF0B81C&1&0001\0";
```

## Issues:
Couldn't deduce GUID for file_interface programmatically, looks like it's the same in every OS


## Registry entries examples (HP LaserJet M104a)

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A\VNF4L07878
ClassGUID = {36fc9e60-c465-11cf-8056-444553540000}

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_00\7&2f1a428f&0&0000
ClassGUID = {36fc9e60-c465-11cf-8056-444553540000}
DeviceDesc = @usbprint.inf,%usbprint.devicedesc%;USB Printing Support

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_01\7&2f1a428f&0&0001\
ClassGUID = {88bae032-5a81-49f0-bc3d-a4ff138216d6}
DeviceDesc = @winusb.inf,%usb\ms_comp_winusb.devicedesc%;WinUsb Device
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_01\7&2f1a428f&0&0001\Device Parameters
DeviceInterfaceGUID = {03ED8E60-777A-48C8-903E-73A76923F00A}

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_02\7&2f1a428f&0&0001\
Class GUID {36fc9e60-c465-11cf-8056-444553540000}
DeviceDesc = HP LaserJet M101-M106(REST)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_02\7&2f1a428f&0&0001\Device Parameters
DeviceInterfaceGUID {350BD08C-9FEE-4264-961C-1709942635C9}
REST 1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_03\7&2f1a428f&0&0001\
ClassGUID = {36fc9e60-c465-11cf-8056-444553540000}
DeviceDesc = HP LaserJet M101-M106(IPP WinUSB)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_03\7&2f1a428f&0&0001\Device Parameters
DeviceInterfaceGUID = {4E5B5531-AC60-4623-8672-BD70F28DE4CC}

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_03F0&PID_612A&MI_03\7&2f1a428f&0&0001\
Class GUID = {36fc9e60-c465-11cf-8056-444553540000}
Device desc = HP LaserJet M101-M106(IPP1 WinUSB)
```
