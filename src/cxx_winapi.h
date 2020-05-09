#include <windows.h>
#include <winusb.h>
#include <aclapi.h>
#include <accctrl.h>
#include <cfgmgr32.h>

#include <iostream>
#include <list>

struct PipesInfo {
  UCHAR pipe_id_in;
  UCHAR pipe_id_out; 
};

class CxxWinapi {
  using device_instance_identifiers_list = std::list<std::string>;
  using device_properties_list = std::list<std::string>;

  public:
    using p_dev_interface_guid = GUID*;
    using p_class_interface_guid = GUID*;
    using winusb_interface_handle = WINUSB_INTERFACE_HANDLE;
    using file_interface_handle = HANDLE;

    CxxWinapi();
    CxxWinapi(std::string multi_interface_id);
    ~CxxWinapi();

    winusb_interface_handle get_winusb_handle(const std::string& vid, const std::string& pid);
    file_interface_handle get_file_interface_handle(const std::string& vid, const std::string& pid); 

    PipesInfo get_pipes_info(winusb_interface_handle winusb_iface_handle); 

    bool write_pipe_async(winusb_interface_handle winusb_iface_handle, const PipesInfo& pipes_info, const std::string& out_package = std::string{});
    bool write_file_async(winusb_interface_handle file_iface_handle, const std::string& out_package = std::string{});
    std::string read_pipe_async(file_interface_handle winusb_iface_handle, const PipesInfo& pipes_info);
    std::string read_file_async(file_interface_handle file_iface_handle);

    std::string get_status_from_html(const std::string& printer_response);

    bool set_security();

  private:

    device_properties_list get_device_instance_properties(int spdrp_property);
    device_instance_identifiers_list get_usb_device_instance_identifiers(const std::string& vid, const std::string& pid);
    device_instance_identifiers_list get_all_device_instance_identifiers(const std::string& vid, const std::string& pid);
    p_dev_interface_guid get_device_interface_guid(const std::string& device_instance_identifier);
    p_class_interface_guid get_class_interface_guid(const std::string& vid, const std::string& pid, const std::string& search_string = "MI_01");
    winusb_interface_handle obtain_winusb_handle(p_dev_interface_guid device_interface_guid, const std::string& device_instance_identifier);
    file_interface_handle obtain_file_interface_handle(p_class_interface_guid device_interface_guid, const std::string& device_instance_identifier);

    std::wstring get_string_reg_key(const std::wstring& registry_path, const std::wstring &strValueName, const std::wstring &strDefaultValue);

    std::wstring ansistring_to_wide(std::string const &Str, UINT CodePage = CP_ACP);
    std::string widestring_to_ansi(std::wstring const &Str, UINT CodePage = CP_ACP);

    std::string hexStr2(unsigned char* data, int len) {
      std::string s(len * 2, ' ');
      for (int i = 0; i < len; ++i) {
        s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
      }
      return s;
    }

    std::string _mi_id;

    HANDLE _h_drive;

    constexpr static char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
};
