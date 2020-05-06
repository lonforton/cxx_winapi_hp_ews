#include <windows.h>
#include <winusb.h>
#include <setupapi.h>
#include <aclapi.h>
#include <accctrl.h>
#include <cfgmgr32.h>

#include <iostream>
#include <codecvt>
#include <locale>
#include <list>

struct PipesInfo {
  UCHAR pipe_id_in;
  UCHAR pipe_id_out; 
};

class CxxWinapi {
  using wstring_converter = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>;  
  using device_instance_identifiers_list = std::list<std::string>;
  using device_properties_list = std::list<std::string>;

  public:
    using p_dev_interface_guid = GUID*;
    using win_usb_handle = WINUSB_INTERFACE_HANDLE;

    device_properties_list get_device_instance_properties(int spdrp_property);
    device_instance_identifiers_list get_device_instance_identifiers(const std::string& vid, const std::string& pid);
    p_dev_interface_guid get_device_interface_guid(const std::string& device_instance_identifier);
    win_usb_handle get_win_usb_handle(p_dev_interface_guid device_interface_guid, const std::string& device_instance_identifier);
    PipesInfo get_pipes_info(win_usb_handle winusb_interface_handle); 

    bool write_pipe_async(win_usb_handle winusb_interface_handle, const PipesInfo& pipes_info, const std::string& write_package = std::string{});
    std::string read_pipe_async(win_usb_handle winusb_interface_handle, const PipesInfo& pipes_info);

    std::string get_status_from_html(const std::string& printer_answer);

    bool set_security();

  private:

    std::string get_device_property(HDEVINFO hdevinfo, SP_DEVINFO_DATA DeviceInfoData, int spdrp_property);
    std::wstring get_string_reg_key(const std::wstring& registry_path, const std::wstring &strValueName, const std::wstring &strDefaultValue);

    std::string hexStr2(unsigned char* data, int len) {
      std::string s(len * 2, ' ');
      for (int i = 0; i < len; ++i) {
        s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
      }
      return s;
    }

    wstring_converter converter;

    constexpr static char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

};