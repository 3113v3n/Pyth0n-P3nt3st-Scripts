import netifaces
#from pprint import pprint
# for i in netifaces.interfaces():
#     iface_details = netifaces.ifaddresses(i)
#     pprint(f"Interface: {i} has details:\n {iface_details}")

class IConfig:
    def __init__(self):
        self.interface = None 

    def get_interface(self):
        """
        Get the interface details and return the interface name
        """
        interfaces = netifaces.interfaces()
        selected = input(f"Select an interface you running the script on: {interfaces}: ")

        if selected in interfaces:
            self.interface = selected
        else:
            print(f"Invalid interface selected. Please select one of: {interfaces}")
            self.get_interface()

    def get_active_interface(self):
        """"Getting the active interface"""
        
        try:
            active_ = netifaces.gateways()
            default_gateway:tuple = active_[2][0]
            
            if default_gateway:
                interface_tuple = default_gateway
                return interface_tuple
            else:
                print("No active interface found.")
        except (KeyError, AttributeError, IndexError):
            pass

if __name__ == "__main__":
    config = IConfig()
    #config.get_interface()
    #print(f"Selected interface: {config.interface}")
    gateway,interface,_ =config.get_active_interface()
    print(f"Active interface: {interface} with gateway: {gateway}")