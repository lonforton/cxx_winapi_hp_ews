#include "cxx_winapi.h"

#include <setupapi.h>

#include <sstream>
#include <vector>

CxxWinapi::CxxWinapi()
{
  _mi_id += "MI_01";
}

CxxWinapi::CxxWinapi(std::string multi_interface_id)
  : _mi_id(multi_interface_id)
{

}

CxxWinapi::~CxxWinapi()
{
  if(_h_drive) {
    CloseHandle(_h_drive);
  }
}

CxxWinapi::device_properties_list CxxWinapi::get_device_instance_properties(int spdrp_property) 
{
  device_properties_list device_props_list;  

  HDEVINFO hDevInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  hDevInfo = SetupDiGetClassDevsW(NULL, L"USB", 0, DIGCF_ALLCLASSES | DIGCF_PROFILE);

  if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cout << "hDevInfo INVALID_HANDLE_VALUE" << std::endl;
    return device_instance_identifiers_list{};
  }

  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); ++i) {
    DWORD DataT;
    LPWSTR buffer = NULL;
    DWORD buffersize = 0;

    while (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &DeviceInfoData, spdrp_property,
                                              &DataT, (PBYTE)buffer, buffersize, &buffersize)) {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        if (buffer) LocalFree(buffer);
        buffer = (LPWSTR)LocalAlloc(LPTR, buffersize * 2);
      }
      else {
        break;
      }
    }

    if (buffer != NULL) {
      device_props_list.emplace_back(widestring_to_ansi(std::wstring(buffer)));
    }

    if (buffer) LocalFree(buffer);

  }

  if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS) {
    return device_properties_list{};
  }

  SetupDiDestroyDeviceInfoList(hDevInfo);

  return device_props_list;
}

CxxWinapi::device_instance_identifiers_list
CxxWinapi::get_usb_device_instance_identifiers(const std::string& vid, const std::string& pid)
{
  device_instance_identifiers_list devices_list;

  std::wstring device_to_find = std::wstring().append(L"USB\\VID_").append(ansistring_to_wide(vid))
                                              .append(L"&PID_").append(ansistring_to_wide(pid));

  HDEVINFO hDevInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  hDevInfo = SetupDiGetClassDevsW(NULL, L"USB", 0, DIGCF_ALLCLASSES | DIGCF_PROFILE);

  if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cerr << "hDevInfo INVALID_HANDLE_VALUE" << std::endl;
    return device_instance_identifiers_list{};
  }

  ULONG device_ids_buff_len = 200;
  PWCHAR device_ids_buff = new WCHAR[device_ids_buff_len];

  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); ++i) {    
    CONFIGRET ret = CM_Get_Device_IDW(DeviceInfoData.DevInst, device_ids_buff, device_ids_buff_len, 0);
    if (ret == CR_SUCCESS) {      
      if (wcsstr(device_ids_buff, device_to_find.c_str())) {
        devices_list.emplace_back(widestring_to_ansi(std::wstring(device_ids_buff)));
      }
    } 
    else {
      //std::cout << "CM_Get_Device_IDW error " << ret << " for usb device " << std::to_string(i) << std::endl;
    }
  }

  if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS) {
    return device_instance_identifiers_list{};
  }

  SetupDiDestroyDeviceInfoList(hDevInfo);

  return devices_list;
}

CxxWinapi::device_instance_identifiers_list CxxWinapi::get_all_device_instance_identifiers(const std::string& vid, const std::string& pid) {
  device_instance_identifiers_list devices_list;

  std::wstring device_to_find = std::wstring().append(L"USB\\VID_").append(ansistring_to_wide(vid))
                                              .append(L"&PID_").append(ansistring_to_wide(pid));

  HDEVINFO hDevInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  hDevInfo = SetupDiGetClassDevsW(NULL, NULL, 0, DIGCF_ALLCLASSES | DIGCF_PROFILE);

  if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cout << "hDevInfo error INVALID_HANDLE_VALUE" << std::endl;
    return device_instance_identifiers_list{};
  }

  ULONG device_ids_buff_len = 200;
  PWCHAR device_ids_buff = new WCHAR[device_ids_buff_len];

  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); ++i) {    
    CONFIGRET ret = CM_Get_Device_IDW(DeviceInfoData.DevInst, device_ids_buff, device_ids_buff_len, 0);
    if (ret == CR_SUCCESS) {      
      if (wcsstr(device_ids_buff, device_to_find.c_str())) {
        devices_list.emplace_back(widestring_to_ansi(std::wstring(device_ids_buff)));
      }
    } 
    else {
      //std::cout << "CM_Get_Device_IDW error " << ret << " for usb device " << std::to_string(i) << std::endl;
    }
  }

  if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS) {
    return device_instance_identifiers_list{};
  }

  SetupDiDestroyDeviceInfoList(hDevInfo);

  return devices_list;
}

CxxWinapi::p_dev_interface_guid CxxWinapi::get_device_interface_guid(const std::string& device_instance_identifier)
{
  std::wstring registry_path = std::wstring().append(L"SYSTEM\\CurrentControlSet\\Enum\\")
                                             .append(ansistring_to_wide(device_instance_identifier))
                                             .append(L"\\Device Parameters");  

  std::wstring guid_reg_value = get_string_reg_key(registry_path, L"DeviceInterfaceGUID", L"");    

  GUID *guid = new GUID();

  IIDFromString(guid_reg_value.c_str(), (LPIID)guid);  

  return guid;
}

CxxWinapi::p_class_interface_guid
CxxWinapi::get_class_interface_guid(const std::string& vid, const std::string& pid, const std::string& search_string)
{

  std::wstring device_to_find = std::wstring().append(L"USB\\VID_").append(ansistring_to_wide(vid))
                                              .append(L"&PID_").append(ansistring_to_wide(pid))
                                              .append(L"&").append(ansistring_to_wide(search_string));                                             

  HDEVINFO hDevInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  hDevInfo = SetupDiGetClassDevsW(NULL, NULL, 0, DIGCF_ALLCLASSES | DIGCF_PROFILE);

  if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cerr << "hDevInfo error INVALID_HANDLE_VALUE" << std::endl;
    return NULL;
  }

  ULONG device_ids_buff_len = 200;
  PWCHAR device_ids_buff = new WCHAR[device_ids_buff_len];

  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); ++i) {    
    CONFIGRET ret = CM_Get_Device_IDW(DeviceInfoData.DevInst, device_ids_buff, device_ids_buff_len, 0);
    if (ret == CR_SUCCESS) {      
      
      if (wcsstr(device_ids_buff, device_to_find.c_str())) {
        
       ULONG  pulRegDataType = 0;
       ULONG  pulLength = 0;
       CM_Get_DevNode_Registry_PropertyW(DeviceInfoData.DevInst, CM_DRP_DRIVER, &pulRegDataType, NULL, &pulLength, 0);
       PVOID *void_buffer = new PVOID[pulLength];
       CM_Get_DevNode_Registry_PropertyW(DeviceInfoData.DevInst, CM_DRP_DRIVER, &pulRegDataType, void_buffer , &pulLength, 0);


      delete [] void_buffer;

      }
    } 
    else {
      std::cerr << "CM_Get_Device_IDW error " << ret << " for device " << std::to_string(i) << std::endl;
    }
  }

  if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS) {
    return NULL;
  }

  SetupDiDestroyDeviceInfoList(hDevInfo);

  constexpr GUID GUID_DEVINTERFACE_HP_FILE = {0x6bdd1fc6, 0x810f, 0x11d0, { 0xbe, 0xc7, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f}};

  GUID *guid = (GUID*)(void*)&GUID_DEVINTERFACE_HP_FILE;

  return guid;
}

bool CxxWinapi::set_security() 
{
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID adminGroup;

  bool ret = AllocateAndInitializeSid(&ntAuthority, 1, 0, 0, 0, 0, 0, 0, 0, 0, &adminGroup);
  if (!ret) {
    std::cout << "AllocateAndInitializeSid error " << GetLastError() << std::endl;
    return false;
  }

  EXPLICIT_ACCESS_W explicit_access;
  ZeroMemory(&explicit_access, sizeof(EXPLICIT_ACCESS_W));
  explicit_access.grfAccessPermissions = STANDARD_RIGHTS_ALL;
  explicit_access.grfAccessMode = SET_ACCESS;
  explicit_access.grfInheritance = 0;

  TRUSTEE_W trustee;
  BuildTrusteeWithSidW(&trustee, adminGroup);
  explicit_access.Trustee = trustee;

  PACL p_new_acl;

  DWORD ret_dw = SetEntriesInAclW(1, &explicit_access, NULL, &p_new_acl);
  if (ret_dw != ERROR_SUCCESS) {
    std::cout << "SetEntriesInAclW error " << GetLastError() << std::endl;
    return false;
  }

  SECURITY_DESCRIPTOR securityDescriptor;
  ZeroMemory(&securityDescriptor, sizeof(SECURITY_DESCRIPTOR));
  ret_dw = InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
  if (!ret_dw) {
    std::cout << "InitializeSecurityDescriptor error " << GetLastError()  << std::endl;
    return false;
  }

  ret_dw = SetSecurityDescriptorDacl(&securityDescriptor, TRUE, p_new_acl, FALSE);
  if (!ret_dw) {
    std::cout << "SetSecurityDescriptorDacl error " << GetLastError() << std::endl;
    return 0;
  }

  LocalFree(p_new_acl);
  FreeSid(adminGroup);

  return true;
}

CxxWinapi::winusb_interface_handle
CxxWinapi::obtain_winusb_handle(p_dev_interface_guid dev_interface_guid, const std::string& device_instance_identifier)
{
  HDEVINFO hDevInfo = SetupDiGetClassDevsW(dev_interface_guid, ansistring_to_wide(device_instance_identifier).c_str(), NULL, DIGCF_DEVICEINTERFACE);
	if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cerr << "Invalid SetupDiGetClassDevs" << GetLastError() << std::endl;
		return NULL;
	}

  SP_DEVICE_INTERFACE_DATA devInterfaceData = {0};
  devInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
  BYTE Buf[1024];
  PSP_DEVICE_INTERFACE_DETAIL_DATA_W pspdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)Buf;  
  DWORD dwIndex = 0;

  bool bRet = SetupDiEnumDeviceInterfaces(hDevInfo, NULL, dev_interface_guid, dwIndex, &devInterfaceData);
  if (!bRet) {
    std::cerr << "SetupDiEnumDeviceInterfaces error " << GetLastError() << std::endl;
    return NULL;
  }

  SP_DEVICE_INTERFACE_DATA spdid;
  spdid.cbSize = sizeof(spdid);

  SetupDiEnumInterfaceDevice(hDevInfo, NULL, dev_interface_guid, dwIndex, &spdid);

  DWORD dwSize = 0;
  SetupDiGetDeviceInterfaceDetailW(hDevInfo, &spdid, NULL, 0, &dwSize, NULL);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    std::cerr << "SetupDiGetDeviceInterfaceDetailW error" << std::endl;
    return NULL;
  } else if (dwSize == 0 && dwSize > sizeof(Buf)) {
    std::cerr << "SetupDiGetDeviceInterfaceDetailW with NULL - returned size is 0 or small" << std::endl;
    return NULL;
  }

  pspdidd->cbSize = sizeof(*pspdidd); 
  SP_DEVINFO_DATA spdd;
  ZeroMemory((PVOID)&spdd, sizeof(spdd));
  spdd.cbSize = sizeof(spdd);

  long res = SetupDiGetDeviceInterfaceDetailW(hDevInfo, &spdid, pspdidd, dwSize, &dwSize, &spdd);
  if (!res) {
    std::cerr << "Invalid SetupDiGetDeviceInterfaceDetail " << GetLastError() << std::endl;
    return NULL;
  }

  _h_drive = CreateFileW(pspdidd->DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
  if (_h_drive == INVALID_HANDLE_VALUE) {
    std::cerr << "CreateFileW error " << GetLastError() << " for " << device_instance_identifier << std::endl;
    return NULL;
  }

  WINUSB_INTERFACE_HANDLE winusb_interface_handle;

  if (!WinUsb_Initialize(_h_drive, &winusb_interface_handle)) {
    std::cout << "WinUsb_Initialize error " << GetLastError() << std::endl;
    return NULL;
  }

  SetupDiDestroyDeviceInfoList(hDevInfo);

  return winusb_interface_handle;
}

CxxWinapi::winusb_interface_handle CxxWinapi::get_winusb_handle(const std::string& vid, const std::string& pid) 
{
  std::string device_instance_identifier;
  auto devices_identifiers = get_usb_device_instance_identifiers(vid, pid);
  for(const auto& item : devices_identifiers) {    
    if(item.find(_mi_id) != std::string::npos) {   
        device_instance_identifier += item; 
        break;
    }           
  }  

  if(device_instance_identifier.empty()) {
    std::cerr << "usb device not found" << std::endl;
    return NULL;
  }

  p_dev_interface_guid device_interface_guid = get_device_interface_guid(device_instance_identifier);

  if(device_interface_guid == NULL) {
    std::cerr << "can't get device_interface_guid" << std::endl;
    return NULL;
  }

  CxxWinapi::winusb_interface_handle winusb_iface_handle;
  for(const auto& item : devices_identifiers) {    
    if(item.find(_mi_id) != std::string::npos) { 
      winusb_iface_handle = obtain_winusb_handle(device_interface_guid, item);
      if(winusb_iface_handle) {
        device_instance_identifier = item;
        break;        
      } 
    }           
  }

  return winusb_iface_handle;
}

CxxWinapi::file_interface_handle CxxWinapi::obtain_file_interface_handle(p_class_interface_guid dev_interface_guid, const std::string& device_instance_identifier)
{  
  HDEVINFO hDevInfo = SetupDiGetClassDevsW(dev_interface_guid, ansistring_to_wide(device_instance_identifier).c_str(), NULL, DIGCF_DEVICEINTERFACE);
	if (hDevInfo == INVALID_HANDLE_VALUE) {
    std::cout << "SetupDiGetClassDevs error INVALID_HANDLE_VALUE" << std::endl;
		return NULL;
	}

  SP_DEVICE_INTERFACE_DATA devInterfaceData = {0};
  devInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
  BYTE Buf[1024];
  PSP_DEVICE_INTERFACE_DETAIL_DATA_W pspdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)Buf;  
  DWORD dwIndex = 0;

  bool bRet = SetupDiEnumDeviceInterfaces(hDevInfo, NULL, dev_interface_guid, dwIndex, &devInterfaceData);
  if (!bRet) {
    std::cerr << "SetupDiEnumDeviceInterfaces (obtain_file_interface_handle) error " << GetLastError() << std::endl;
    return NULL;
  }

  SP_DEVICE_INTERFACE_DATA spdid;
  spdid.cbSize = sizeof(spdid);

  SetupDiEnumInterfaceDevice(hDevInfo, NULL, dev_interface_guid, dwIndex, &spdid);

  DWORD dwSize = 0;
  SetupDiGetDeviceInterfaceDetailW(hDevInfo, &spdid, NULL, 0, &dwSize, NULL);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    std::cout << "SetupDiGetDeviceInterfaceDetailW error" << std::endl;
    return NULL;
  } else if (dwSize == 0 && dwSize > sizeof(Buf)) {
    std::cout << "SetupDiGetDeviceInterfaceDetailW with NULL - returned size is 0 or too small" << std::endl;
    return NULL;
  }

  pspdidd->cbSize = sizeof(*pspdidd); 
  SP_DEVINFO_DATA spdd;
  ZeroMemory((PVOID)&spdd, sizeof(spdd));
  spdd.cbSize = sizeof(spdd);

  long res = SetupDiGetDeviceInterfaceDetailW(hDevInfo, &spdid, pspdidd, dwSize, &dwSize, &spdd);
  if (!res) {
    std::cout << "Invalid SetupDiGetDeviceInterfaceDetail " << GetLastError() << std::endl;
    return NULL;
  }

  HANDLE hDrive = CreateFileW(pspdidd->DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
  if (hDrive == INVALID_HANDLE_VALUE) {
    std::cout << "CreateFileW error " << GetLastError() << " for " << device_instance_identifier << std::endl;
    return NULL;
  }

  return hDrive;
}

CxxWinapi::file_interface_handle CxxWinapi::get_file_interface_handle(const std::string& vid, const std::string& pid) 
{  
  std::string device_instance_identifier;
  auto devices_identifiers = get_all_device_instance_identifiers(vid, pid);
  for (const auto& item : devices_identifiers) {
    if (item.find(_mi_id) != std::string::npos) {
      device_instance_identifier += item;
      break;
    }
  }

  if (device_instance_identifier.empty()) {
    std::cout << "device not found" << std::endl;
    return NULL;
  }

  p_class_interface_guid class_interface_guid = get_class_interface_guid(vid, pid);

  file_interface_handle file_iface_handle = obtain_file_interface_handle(class_interface_guid, device_instance_identifier);

  return file_iface_handle;
}

PipesInfo CxxWinapi::get_pipes_info(winusb_interface_handle winusb_iface_handle)
{
  PipesInfo pipes_info = {0};

  USB_INTERFACE_DESCRIPTOR *eUsbInterfaceDescriptor = new USB_INTERFACE_DESCRIPTOR();
  bool ret = WinUsb_QueryInterfaceSettings(winusb_iface_handle, 0, eUsbInterfaceDescriptor);
  if (!ret) {
    std::cout << "WinUsb_QueryInterfaceSettings error " << GetLastError() << std::endl;
    return pipes_info;
  }

  WINUSB_PIPE_INFORMATION pipe_info;
  ZeroMemory(&pipe_info, sizeof(WINUSB_PIPE_INFORMATION));

  for (int i = 0; i < eUsbInterfaceDescriptor->bNumEndpoints; ++i) {
    if (WinUsb_QueryPipe(winusb_iface_handle, 0, i, &pipe_info)) {
      if (pipe_info.PipeType == UsbdPipeTypeBulk) {
        if (USB_ENDPOINT_DIRECTION_OUT(pipe_info.PipeId)) {
          pipes_info.pipe_id_out = pipe_info.PipeId;
        }
        if (USB_ENDPOINT_DIRECTION_IN(pipe_info.PipeId)) {
          pipes_info.pipe_id_in = pipe_info.PipeId;
        }
      }
    }
  }

  return pipes_info;
}

bool CxxWinapi::write_pipe_async(winusb_interface_handle winusb_iface_handle, const PipesInfo& pipes_info, const std::string& out_package)
{  
  // posible to convert out_package to hex using hex2str

   UCHAR pipe_id = pipes_info.pipe_id_out;
   UCHAR default_package_buffer[] = "\x47\x45\x54\x20\x2f\x69\x6e\x66\x6f\x5f\x64\x65\x76\x69\x63\x65\x53\x74\x61\x74\x75\x73\x2e\x68\x74\x6d\x6c\x3f\x74\x61\x62\x3d\x48\x6f\x6d\x65\x26\x6d\x65\x6e\x75\x3d\x44\x65\x76\x53\x74\x61\x74\x75\x73\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x69\x6d\x61\x67\x65\x2f\x67\x69\x66\x2c\x20\x69\x6d\x61\x67\x65\x2f\x6a\x70\x65\x67\x2c\x20\x69\x6d\x61\x67\x65\x2f\x70\x6a\x70\x65\x67\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x6d\x73\x2d\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x61\x6d\x6c\x2b\x78\x6d\x6c\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x6d\x73\x2d\x78\x62\x61\x70\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x76\x6e\x64\x2e\x6d\x73\x2d\x65\x78\x63\x65\x6c\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x76\x6e\x64\x2e\x6d\x73\x2d\x70\x6f\x77\x65\x72\x70\x6f\x69\x6e\x74\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6d\x73\x77\x6f\x72\x64\x2c\x20\x2a\x2f\x2a\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x72\x75\x2d\x52\x55\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x4b\x65\x65\x70\x2d\x41\x6c\x69\x76\x65\x0d\x0a\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6c\x61\x6e\x67\x3d\x72\x75\x73\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x35\x30\x30\x30\x32\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x35\x30\x30\x30\x32\x2f\x69\x6e\x66\x6f\x5f\x64\x65\x76\x69\x63\x65\x53\x74\x61\x74\x75\x73\x2e\x68\x74\x6d\x6c\x3f\x74\x61\x62\x3d\x48\x6f\x6d\x65\x26\x6d\x65\x6e\x75\x3d\x44\x65\x76\x53\x74\x61\x74\x75\x73\x0d\x0a\x55\x41\x2d\x43\x50\x55\x3a\x20\x41\x4d\x44\x36\x34\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x34\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x38\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x32\x3b\x20\x57\x69\x6e\x36\x34\x3b\x20\x78\x36\x34\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b\x20\x2e\x4e\x45\x54\x34\x2e\x30\x43\x3b\x20\x2e\x4e\x45\x54\x34\x2e\x30\x45\x29\x0d\x0a\x0d\x0a\x00";

  UCHAR *write_buffer;
  if(out_package.empty()) {
    write_buffer = default_package_buffer;
  }
  else {
    write_buffer = new UCHAR[out_package.size() + 1];
    std::copy(out_package.begin(), out_package.end(), write_buffer);
    write_buffer[out_package.length()] = 0;
  }

  ULONG write_buffer_length = strlen((const char *)write_buffer);
  ULONG length_transferred = 0;   // not used, only need for non-overlapped write

  OVERLAPPED m_overlapped_write;
  ZeroMemory(&m_overlapped_write, sizeof(OVERLAPPED));
  m_overlapped_write.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  
  if (!WinUsb_WritePipe(winusb_iface_handle, pipe_id, write_buffer, write_buffer_length, &length_transferred, &m_overlapped_write))
  {
    if (GetLastError() != ERROR_IO_PENDING) {
      std::cerr << "WritePipe error (not io_pending) " << GetLastError() << std::endl;
      return false;
    }
  }

  DWORD wait_result = WaitForSingleObject(m_overlapped_write.hEvent, 100);
  if(wait_result == WAIT_OBJECT_0) {
    DWORD bytes_written = 0;
    bool over_res = WinUsb_GetOverlappedResult(winusb_iface_handle, &m_overlapped_write, &bytes_written, TRUE);
     if (!over_res) {
        std::cout << "WinUsb_GetOverlappedResult error " << GetLastError() << std::endl;
        return false;
    }

    if(bytes_written > 0) {
      std::cout << "written to pipe " << +pipe_id << " - " << bytes_written << " bytes" << std::endl;
    }
    else {
      return false;
    }
  }

  CloseHandle(m_overlapped_write.hEvent);

  if(!out_package.empty()) {
    delete [] write_buffer;
  }

  return true;
}

bool CxxWinapi::write_file_async(file_interface_handle file_iface_handle, const std::string& out_package)
{
  // posible to convert out_package to hex using hex2str

  UCHAR default_package_buffer[] = "\x47\x45\x54\x20\x2f\x69\x6e\x66\x6f\x5f\x64\x65\x76\x69\x63\x65\x53\x74\x61\x74\x75\x73\x2e\x68\x74\x6d\x6c\x3f\x74\x61\x62\x3d\x48\x6f\x6d\x65\x26\x6d\x65\x6e\x75\x3d\x44\x65\x76\x53\x74\x61\x74\x75\x73\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x69\x6d\x61\x67\x65\x2f\x67\x69\x66\x2c\x20\x69\x6d\x61\x67\x65\x2f\x6a\x70\x65\x67\x2c\x20\x69\x6d\x61\x67\x65\x2f\x70\x6a\x70\x65\x67\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x6d\x73\x2d\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x61\x6d\x6c\x2b\x78\x6d\x6c\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x6d\x73\x2d\x78\x62\x61\x70\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x76\x6e\x64\x2e\x6d\x73\x2d\x65\x78\x63\x65\x6c\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x76\x6e\x64\x2e\x6d\x73\x2d\x70\x6f\x77\x65\x72\x70\x6f\x69\x6e\x74\x2c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6d\x73\x77\x6f\x72\x64\x2c\x20\x2a\x2f\x2a\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x72\x75\x2d\x52\x55\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x4b\x65\x65\x70\x2d\x41\x6c\x69\x76\x65\x0d\x0a\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6c\x61\x6e\x67\x3d\x72\x75\x73\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x35\x30\x30\x30\x32\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x35\x30\x30\x30\x32\x2f\x69\x6e\x66\x6f\x5f\x64\x65\x76\x69\x63\x65\x53\x74\x61\x74\x75\x73\x2e\x68\x74\x6d\x6c\x3f\x74\x61\x62\x3d\x48\x6f\x6d\x65\x26\x6d\x65\x6e\x75\x3d\x44\x65\x76\x53\x74\x61\x74\x75\x73\x0d\x0a\x55\x41\x2d\x43\x50\x55\x3a\x20\x41\x4d\x44\x36\x34\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x34\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x38\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x32\x3b\x20\x57\x69\x6e\x36\x34\x3b\x20\x78\x36\x34\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b\x20\x2e\x4e\x45\x54\x34\x2e\x30\x43\x3b\x20\x2e\x4e\x45\x54\x34\x2e\x30\x45\x29\x0d\x0a\x0d\x0a\x00";

  UCHAR *write_buffer;
  if(out_package.empty()) {
    write_buffer = default_package_buffer;
  }
  else {
    write_buffer = new UCHAR[out_package.size() + 1];
    std::copy(out_package.begin(), out_package.end(), write_buffer);
    write_buffer[out_package.length()] = 0;
  }

  ULONG write_buffer_length = strlen((const char *)write_buffer);
  ULONG length_transferred = 0;   // not used, only need for non-overlapped write

  OVERLAPPED m_overlapped_write;
  ZeroMemory(&m_overlapped_write, sizeof(OVERLAPPED));
  m_overlapped_write.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

  if (!WriteFile(file_iface_handle, write_buffer, write_buffer_length, &length_transferred, &m_overlapped_write))
  {
    if (GetLastError() != ERROR_IO_PENDING) {
      std::cerr << "WriteFile error (not io_pending) " << GetLastError() << std::endl;
      return false;
    }
  }

  DWORD bytes_written = 0;
  bool over_res = GetOverlappedResult(file_iface_handle, &m_overlapped_write, &bytes_written, TRUE);
  if (!over_res) {
    std::cout << "GetOverlappedResult error " << GetLastError() << std::endl;
    return false;
  }

  if (bytes_written > 0) {
    std::cout << "written " << bytes_written << " bytes" << std::endl;
  } else {
    return false;
  }

  return true;

}

std::string CxxWinapi::read_pipe_async(winusb_interface_handle winusb_iface_handle, const PipesInfo& pipes_info)
{
  std::string printer_response;

  OVERLAPPED overlapped_read;
  ZeroMemory(&overlapped_read, sizeof(OVERLAPPED));
  overlapped_read.hEvent = CreateEventW(NULL, TRUE, TRUE, NULL);

  ULONG read_buffer_size = 4096;
  UCHAR pipe_id_in = pipes_info.pipe_id_in;
  UCHAR *read_buffer = (UCHAR *)LocalAlloc(LPTR, sizeof(UCHAR) * read_buffer_size);  
  ULONG bytes_readed_readpipe = 0;     // not used, only need for non-overlapped read
  DWORD bytes_readed = 0;

  bool read_ended = false;
  while (!read_ended)
  {
    if (!WinUsb_ReadPipe(winusb_iface_handle, pipe_id_in, read_buffer, read_buffer_size, &bytes_readed_readpipe, &overlapped_read))
    {
      DWORD read_pipe = GetLastError();      
      if (read_pipe != ERROR_IO_PENDING) {
        std::cout << "Last error not pending " << GetLastError() << std::endl;
        read_ended = true;
        break;
      }
    }

    DWORD wait_result = WaitForSingleObject(overlapped_read.hEvent, INFINITE);
    if (wait_result == WAIT_OBJECT_0)
    {
      bool over_res = WinUsb_GetOverlappedResult(winusb_iface_handle, &overlapped_read, &bytes_readed, TRUE);      
      if (!over_res) {
        std::cout << "WinUsb_GetOverlappedResult error " << GetLastError() << std::endl;
        return printer_response;
      }
      
      if (bytes_readed > 0)
      {
        printer_response.append(reinterpret_cast<const char *>(read_buffer));

        if (printer_response.find("</html>") != std::string::npos) {
          std::cout << "end of package found, reading stopped" << std::endl;
          break;
        }
      }

      ResetEvent(overlapped_read.hEvent);
    }
    else if (wait_result == WAIT_TIMEOUT)
    {
      std::cout << "wait_timeout" << std::endl;
      return printer_response;
    }
    else
    {
      std::cout << "wait unknown" << std::endl;
      return printer_response;
    }
  }

  CloseHandle(overlapped_read.hEvent);

  LocalFree(read_buffer);

  return printer_response;
}

std::string CxxWinapi::read_file_async(file_interface_handle file_iface_handle) 
{
  std::string printer_response;

  OVERLAPPED overlapped_read;
  ZeroMemory(&overlapped_read, sizeof(OVERLAPPED));
  overlapped_read.hEvent = CreateEventW(NULL, TRUE, TRUE, NULL);

  ULONG read_buffer_size = 4096;
  UCHAR *read_buffer = (UCHAR *)LocalAlloc(LPTR, sizeof(UCHAR) * read_buffer_size);  
  ULONG bytes_readed_readpipe = 0;
  DWORD bytes_readed = 0;

  bool read_ended = false;
  while (!read_ended)
  {
    if (!ReadFile(file_iface_handle, read_buffer, read_buffer_size, &bytes_readed_readpipe, &overlapped_read))
    {
      DWORD read_pipe = GetLastError();      
      if (read_pipe != ERROR_IO_PENDING) {
        std::cout << "ReadFile error (not IO_PENDING) " << GetLastError() << std::endl;
        read_ended = true;
        break;
      }
    }

    DWORD wait_result = WaitForSingleObject(overlapped_read.hEvent, INFINITE);
    if (wait_result == WAIT_OBJECT_0)
    {
      bool over_res = GetOverlappedResult(file_iface_handle, &overlapped_read, &bytes_readed, TRUE);      
      if (!over_res) {
        std::cout << "GetOverlappedResult error " << GetLastError() << std::endl;
        return printer_response;
      }
      
      if (bytes_readed > 0)
      {
        printer_response.append(reinterpret_cast<const char *>(read_buffer));

        if (printer_response.find("</html>") != std::string::npos) {
          std::cout << "end of package found, reading stopped" << std::endl;
          break;
        }
      }

      ResetEvent(overlapped_read.hEvent);
    }
    else if (wait_result == WAIT_TIMEOUT)
    {
      std::cout << "wait_timeout" << std::endl;
      return printer_response;
    }
    else
    {
      std::cout << "wait unknown" << std::endl;
      return printer_response;
    }
  }

  CloseHandle(overlapped_read.hEvent);

  LocalFree(read_buffer);

  return printer_response;
}

std::string CxxWinapi::get_status_from_html(const std::string& printer_response)
{
  auto index = printer_response.find("deviceStatus_tableCell");
  if(index != std::string::npos) {
    std::string status_block(printer_response, index, 200);
    if(status_block.find("Sleep&nbsp;mode") != std::string::npos) {
      return std::string("Sleep mode is on");
    }
    else if(status_block.find("Initializing") != std::string::npos) {
      return std::string("Initializing");
    }
    else if(status_block.find("Printing") != std::string::npos) {
      return std::string("Printing");
    }
    else if(status_block.find("Ready") != std::string::npos) {
      return std::string("Ready");
    }
    else if(status_block.find("Load&nbsp;paper") != std::string::npos) {
      return std::string("Load paper");
    }
    else if(status_block.find("Door&nbsp;is&nbsp;open") != std::string::npos) {
      return std::string("Door is open");
    }    
  }

  return std::string();
}

std::wstring CxxWinapi::get_string_reg_key(const std::wstring& registry_path, const std::wstring &strValueName, const std::wstring &strDefaultValue)
{
  std::wstring strValue;

    HKEY hKey;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  registry_path.c_str(),
                  0, KEY_READ, &hKey);

    strValue = strDefaultValue;
    WCHAR szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    ULONG nError;
    nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
    if (ERROR_SUCCESS == nError)
    {
        strValue = szBuffer;
    }
    return strValue;
}

std::wstring CxxWinapi::ansistring_to_wide(std::string const &Str, UINT CodePage)
{
    DWORD const BuffSize = MultiByteToWideChar(CodePage, 0, Str.c_str(), -1, NULL, 0);
    if (!BuffSize) return NULL;
    std::vector<wchar_t> Buffer;
    Buffer.resize(BuffSize);
    if (!MultiByteToWideChar(CodePage, 0, Str.c_str(), -1, &Buffer[0], BuffSize)) return NULL;
    return (&Buffer[0]);
}

std::string CxxWinapi::widestring_to_ansi(std::wstring const &Str, UINT CodePage)
{
    DWORD const BuffSize = WideCharToMultiByte(CodePage, 0, Str.c_str(), -1, NULL, 0, NULL, NULL);
    if (!BuffSize) return NULL;
    std::vector<char> Buffer;
    Buffer.resize(BuffSize);
    if (!WideCharToMultiByte(CodePage, 0, Str.c_str(), -1, &Buffer[0], BuffSize, NULL, NULL)) return NULL;
    return (&Buffer[0]);
}

