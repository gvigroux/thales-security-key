#Copyright 2025 Thales
#
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its 
#    contributors may be used to endorse or promote products derived from 
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  


from time import sleep
from smartcard import System
import ctypes, os

from fido2.hid import CtapHidDevice
from .hid import CtapHidThalesDevice
from .pcsc import CtapPcscThalesDevice, PcscThalesDevice
from .const import ATRs, thales_vendor_id

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

def is_user_admin() -> bool:
    is_admin = False
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        pass
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        pass
    return is_admin

def check_requirements() -> bool:
    if(os.name == "nt") and ( not is_user_admin() ):
        return False
    return True



def is_thales_device(device):
    if isinstance(device, CtapHidThalesDevice) or isinstance(device, CtapPcscThalesDevice):
        return True
    if isinstance(device, CtapHidDevice) and (device.descriptor.vid == thales_vendor_id):
        return True
    if isinstance(device, CtapPcscDevice): 
        device._conn.connect()           
        for atr in ATRs:
            if( atr.isValid(device.get_atr()) ): 
                return True
    return False


def single_device(thales_only=True, prompt=True, status=0):
    if( thales_only ):
        devices = list(enumerate_thales_devices())
    else:
        devices = list(enumerate_devices())
    if( len(devices) == 0):
        if( prompt ) and ((status == 0) or (status == 1)):
            print(">>> Scanning for Security Key...")
            status = 2
        sleep(1)
        return single_device(thales_only, prompt, status)
    if( len(devices) > 1):
        if( prompt ) and ((status == 0) or (status == 2)):
            print(">>> More than one device found ...")
        sleep(1)
        return single_device(thales_only,prompt,1)
    return devices


def filter_by_serial_number(devices, serial_number):
    if( serial_number == None ) or ( len(devices) == 0):
        return devices
    for index, device in enumerate(devices): 
        if( device.thales_serial_number != serial_number ):
            devices.pop(index)
        return devices
    


def scan_pcsc_devices(wait=False, serial_number = None, reader = None):
    
    pcsc_devices = list(enumerate_pcsc_devices(reader))
    pcsc_devices = filter_by_serial_number(pcsc_devices, serial_number)

    if( len(pcsc_devices) == 0) and ( wait ):
        sleep(1)
        return scan_pcsc_devices(wait, serial_number, reader)    
    
    return pcsc_devices



def scan_devices(thales_only=True, wait=False, fido_only=True, serial_number = None, reader = None):
    
    # Get list of HID devices
    devices = list(enumerate_hid_devices())
     
    for loop_reader in scan_pcsc_readers():
        try:
            devices.append(next(CtapPcscThalesDevice.list_devices(loop_reader.name)))
            break
        except Exception as e:
            pass

        if( not fido_only ):
            try:
                devices.append(next(enumerate_pcsc_devices(loop_reader.name)))
            except:
                pass


    # Remove devices with other serial number
    devices = filter_by_serial_number(devices, serial_number)


    if( len(devices) == 0) and ( wait ):
        try:
            sleep(1)
        except KeyboardInterrupt:
            return []
        return scan_devices(thales_only, wait, fido_only, serial_number, reader)    
 
    return devices

def scan_pcsc_readers():
    return System.readers()



def clean_device_list(devices, pcsc_devices):

    # FIDO 2.0: devices are accessible through HiD and PCSC
    # This loop eliminate PCSC device when the same device is found in HID
    for device1 in devices:
        if(not isinstance(device1, CtapHidThalesDevice)):
            continue
        for index, device2 in enumerate(devices): 
            if(not isinstance(device2, CtapPcscThalesDevice)):
                continue
            if( device1 == device2 ):
                device1.update_from_pcsc(device2)
                devices.pop(index) # Remove device2 from the list


    # FIDO 2.1: FIDO is accessible through HID only but we can get more info through PCSC
    for device in devices:
        if(not isinstance(device, CtapHidThalesDevice)):
            continue
        for pcsc_device in pcsc_devices:
            if( device == pcsc_device ):
                device.update_from_pcsc(pcsc_device)
                pass

    return devices


def enumerate_hid_devices():
    for dev in CtapHidThalesDevice.list_devices():
        yield dev


def enumerate_devices(reader: str = ""):
    reader = str(reader or '')
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices(reader):
            yield dev


def enumerate_thales_devices(reader: str = ""):
    "This method is used to enumerate all the Thales Security Key available on the system."
    reader = str(reader or '')
    for dev in CtapHidThalesDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscThalesDevice.list_devices(reader):
            yield dev

            
def enumerate_pcsc_devices(reader: str = ""):
    "List all available PCSC Thales devices."
    reader = str(reader or '')
    try:
        if CtapPcscDevice:
            for dev in PcscThalesDevice.list_devices(reader):
                dev.close()
                yield dev
            
    except Exception as e:
        pass




