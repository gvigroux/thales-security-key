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

from thalessecuritykey.device import ThalesDevice
from .hid import CtapHidThalesDevice
from .pcsc import PcscThalesDevice
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
    if isinstance(device, ThalesDevice):
        return True
    if isinstance(device, CtapHidDevice) and (device.descriptor.vid == thales_vendor_id):
        return True
    if isinstance(device, CtapPcscDevice): 
        device._conn.connect()           
        for atr in ATRs:
            if( atr.isValid(device.get_atr()) ): 
                return True
    return False




def scan_devices(fido_only=False, thales_only=True, wait=True, serial_number = None, pcsc_reader = None) :
    
    # Get list of valid HID FIDO devices
    devices = list(enumerate_hid_devices(thales_only, serial_number))

    # Add all PCSC valid devices (FIDO & NON-FIDO)
    devices += list(enumerate_pcsc_devices(thales_only, pcsc_reader))

    if( len(devices) == 0) and ( wait ):
        try:
            sleep(1)
        except KeyboardInterrupt:
            return []
        return scan_devices(fido_only, thales_only, wait, serial_number, pcsc_reader)    
 
    return devices



def enumerate_hid_devices(thales_only=True, serial_number = None):
    for dev in CtapHidThalesDevice.list_devices(thales_only, serial_number):
        yield dev


def enumerate_pcsc_devices(thales_only=True, pcsc_reader = None):
    for dev in PcscThalesDevice.list_devices(thales_only, pcsc_reader):
        yield dev

