#include "../src/cxx_winapi.h"

constexpr auto out_package{"GET /info_deviceStatus.html?tab=Home&menu=DevStatus HTTP/1.1\n\
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

int main() 
{
  const std::string vid{"03F0"};
  const std::string pid{"612A"};

  CxxWinapi cxx_winapi("MI_01"); 

  CxxWinapi::winusb_interface_handle winusb_iface_handle = cxx_winapi.get_winusb_handle(vid, pid);

  if (winusb_iface_handle) {
          
    PipesInfo pipes_info = cxx_winapi.get_pipes_info(winusb_iface_handle);   // getting pipes info (USB BULK ENDPOINTS IN and OUT)

    cxx_winapi.write_pipe_async(winusb_iface_handle, pipes_info);       // or cxx_winapi.write_pipe_async(_winusb_interface_handle, pipes_info, out_package);   

    auto printer_response = cxx_winapi.read_pipe_async(winusb_iface_handle, pipes_info);

    auto printer_status = cxx_winapi.get_status_from_html(printer_response);

    std::cout << printer_status << std::endl;
  } 
  else {

    std::cout << "Can't get win_usb handle for any of printers (printer either offline or usb isn't used)" << std::endl; 

    CxxWinapi::file_interface_handle file_iface_handle = cxx_winapi.get_file_interface_handle(vid, pid);
 
    cxx_winapi.write_file_async(file_iface_handle);         // or cxx_winapi.write_file_async(_winusb_interface_handle, out_package); 

    auto printer_response = cxx_winapi.read_file_async(file_iface_handle);

     auto printer_status = cxx_winapi.get_status_from_html(printer_response);

    std::cout << printer_status << std::endl;
  }

  return 0;
}
