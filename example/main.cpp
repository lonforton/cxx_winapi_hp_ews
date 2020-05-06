#include "../src/cxx_winapi.h"

int main() 
{
  const std::string vid{"03F0"};
  const std::string pid{"612A"};

  CxxWinapi cxx_winapi;

  std::string device_instance_identifier;

  // getting all device identifiers \USB\VID_xxxx&PID_xxxx&MI_xx\xxxxxxxxxxxxxxxxxx, then searching for any with MI_01
  auto devices_identifiers = cxx_winapi.get_device_instance_identifiers(vid, pid);
  for(const auto& item : devices_identifiers) {    
    if(item.find("MI_01") != std::string::npos) {   
        device_instance_identifier += item; 
        break;
    }           
  }  

  // getting device interface guid for MI_01 (common for all MI_01)
  CxxWinapi::p_dev_interface_guid device_interface_guid = cxx_winapi.get_device_interface_guid(device_instance_identifier);
  
  // looking for win_usb_handle for current printer for all identifiers with MI_01
  CxxWinapi::win_usb_handle _winusb_interface_handle;
  for(const auto& item : devices_identifiers) {    
    if(item.find("MI_01") != std::string::npos) { 
      _winusb_interface_handle = cxx_winapi.get_win_usb_handle(device_interface_guid, item);
      if(_winusb_interface_handle){
        device_instance_identifier = item;
        break;        
      } 
    }           
  } 

  std::cout << "win usb handle found for " << device_instance_identifier << std::endl;

  if(!_winusb_interface_handle) {
    std::cout << "Can't get win_usb handle for any of printers" << std::endl;
    return 0;
  }

  // getting pipes info (USB BULK ENDPOINTS IN and OUT)
  PipesInfo pipes_info = cxx_winapi.get_pipes_info(_winusb_interface_handle);


std::string out_package{"GET /info_deviceStatus.html?tab=Home&menu=DevStatus HTTP/1.1\n\
Accept: image/gif, image/jpeg, image/pjpeg, application/x-ms-application, application/xaml+xml, application/x-ms-xbap, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*\n\
Accept-Encoding: gzip, deflate\n\
Accept-Language: ru-RU\n\
Connection: Keep-Alive\n\
Cookie: lang=rus\n\
HOST: localhost\n\
Host: localhost:50002\n\
Referer: http://localhost:50002/info_deviceStatus.html?tab=Home&menu=DevStatus\n\
UA-CPU: AMD64\n\
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)\n\
\n\
"};

  cxx_winapi.write_pipe_async(_winusb_interface_handle, pipes_info);   
  // or cxx_winapi.write_pipe_async(_winusb_interface_handle, pipes_info, out_package);

  auto printer_answer = cxx_winapi.read_pipe_async(_winusb_interface_handle, pipes_info);

  auto printer_status = cxx_winapi.get_status_from_html(printer_answer);

  std::cout << printer_status << std::endl;

  return 0;
}
