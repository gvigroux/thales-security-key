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


import hashlib
import struct
import logging
from typing import Iterator,  Tuple

try:
    from fido2.pcsc import CtapPcscDevice, _list_readers, SW_SUCCESS, CardConnection, AID_FIDO
except ImportError:
    CtapPcscDevice = None
    _list_readers  = None
    AID_FIDO       = None 
    SW_SUCCESS     = (0x90, 0x00)

from .device import PkiApplet, ThalesDevice
from .const import *



#******************************************************************************
# Default class for PCSC connection (PKI & FIDO)

class PcscThalesDevice(ThalesDevice):
    def __init__(self, connection: CardConnection, name: str, has_fido: bool = False):
        super().__init__(name, has_fido)
        self._conn = connection
        # The connection is not yet open
        if( self._conn.component.hcard == None):
            self._conn.connect()

        self._check_card_manager()
        self._discovery()
        
        try:
            # Check if the device is a Thales device
            atr = bytes(self._conn.getATR())
            for atr_entry in ATRs:
                if( atr_entry.isValid(atr) ): 
                    self._is_thales_device = True
                    break
        except Exception as e:
            print("Error %r", e)
            pass

    def __repr__(self):
        return f"PcscThalesDevice({self.name}, {self.thales_serial_number})"
    
    def __eq__(self, other): 
        return self.thales_serial_number == other.thales_serial_number
            
    def _discovery_pki(self):        
        if( self._select_by_aid(AID_PIV) ):
            self.pki_applet         = PkiApplet.PIV
        elif( self._select_by_aid(AID_IDPRIME_930) ):
            self.pki_applet         = PkiApplet.IDPRIME_930
            self._is_thales_device  = True # It's a Thales device
        elif( self._select_by_aid(AID_IDPRIME_940) ):
            self.pki_applet         = PkiApplet.IDPRIME_940
            self._is_thales_device  = True # It's a Thales device
    
    def _select_pki_applet(self):
        if( self.pki_applet == PkiApplet.IDPRIME_930 ):
            self._select_by_aid(AID_IDPRIME_930)
            self._is_thales_device  = True # It's a Thales device
        elif( self.pki_applet == PkiApplet.IDPRIME_940 ):
            self._select_by_aid(AID_IDPRIME_940)
            self._is_thales_device  = True # It's a Thales device
        elif( self.pki_applet == PkiApplet.PIV ):
            self._select_by_aid(AID_PIV)
                  
    def _discovery(self):
        """ Discover all applets inside the device; search for S/N"""

        self._discovery_pki()

        if( self._pki_applet == PkiApplet.IDPRIME_930 ) or (self._pki_applet == PkiApplet.IDPRIME_940 ):

            ret, resp = self._read_file(b"\x00\x25")
            if( ret ):
                self._parse_info_file(resp)

            ret, resp = self._read_file(b"\x00\x29")
            if( ret ):
                self._custom_serial_number = resp.decode("utf-8").split("\x00",1)[0].upper() # Works for FIPS

            ret, resp = self._get_data(b"\xDF\x30", 0x00)
            if( ret ):
                self.pki_version = resp[3:]
           
            ret, resp = self._read_file(b"\x02\x01")
            if( ret ):
                self._pki_serial_number = hashlib.md5(resp[4:]).hexdigest()[:16].upper()

        elif( self._pki_applet == PkiApplet.PIV ):    

            ret, resp = self._get_container_data(b"\x5F\xFF\x12")
            if( ret ):
                self._parse_info_file(resp)
                self._is_thales_device  = True # It's a Thales device

            ret, resp = self._get_container_data(b"\x5F\xFF\x13")
            if( ret ):
                self._custom_serial_number = resp[2:].decode("utf-8").upper()
                self._is_thales_device  = True # It's a Thales device

            self._select_by_aid(AID_PIV_ADMIN)
                
            ret, resp = self._get_data(b"\xDF\x30") 
            if( ret ):
                self.pki_version = resp[3:]

    
        if( (self._has_fido != True) 
           and self._select_by_aid(AID_FIDO) ):
            self._has_fido  = True

    def _check_card_manager(self):
        try:
            resp, sw1, sw2 = self._conn.transmit(list(AID_CARD_MANAGER))
        except:
            # Unable to select the Card Manager
            return
        try:
            resp, sw1, sw2 = self._conn.transmit(list(APDU_GET_DETAILS))
            if (sw1, sw2) == SW_SUCCESS:
                self._parse_card_manager(bytes(resp))
            return
        except:
            # Unable to find Thales serial number. Possible for old devices
            pass
        try:
            resp, sw1, sw2 = self._conn.transmit(list(APDU_GET_SN))
            if (sw1, sw2) == SW_SUCCESS:
                self.thales_serial_number = bytes(resp)[3:]
        except:
            # Unable to find Thales serial number. Possible for old devices
            pass

    def close(self) -> None:
        self._conn.disconnect()


    def _read_file(self, file_id, le = 0x00) -> Tuple[bool, bytes]:
        """ Reads a specific file from the device, returns True if successful """
        
        # Select File 
        resp, sw1, sw2 = self._conn.transmit(list(APDU_SELECT_FILE + struct.pack("!B", len(file_id)) + file_id))
        if (sw1, sw2) != SW_SUCCESS:
            logging.debug("Error ["+hex(sw1)+","+hex(sw2)+"] after sending APDU")
            return False, None

        # Read binary
        resp, sw1, sw2 = self._conn.transmit(list(APDU_READ_BINARY + struct.pack("!B", le)))
        if( sw1 == 0x6C ) and ( le == 0x00 ):
            return self._read_file(file_id, sw2)
        if (sw1, sw2) != SW_SUCCESS:
            logging.debug("Error ["+hex(sw1)+","+hex(sw2)+"] after sending APDU")
            return False, None
        
        return True, bytes(resp)
    

    def _get_data(self, data_id , le = 0x00 ) -> Tuple[bool, bytes]:
        if( self.pki_applet == PkiApplet.IDPRIME ):
            apdu = APDU_IDP_GET_DATA + data_id + struct.pack("!B", le)
        else:
            apdu = APDU_PIV_GET_DATA + data_id + struct.pack("!B", le)

        resp, sw1, sw2 = self._conn.transmit(list(apdu))
        if( sw1 == 0x6C ) and ( le == 0x00 ):
            return self._get_data(data_id, sw2)
        if (sw1, sw2) != SW_SUCCESS:
            logging.debug("Error ["+hex(sw1)+","+hex(sw2)+"] after sending APDU")
            return False, bytes(resp)
        return True, bytes(resp)


    def _get_container_data(self, data_id ) -> Tuple[bool, bytes]:
        apdu = APDU_GET_CONTAINER + struct.pack("!B", len(data_id)) + data_id + b"\x00"
        resp, sw1, sw2 = self._conn.transmit(list(apdu))
        if (sw1, sw2) != SW_SUCCESS:
            logging.debug("Error ["+hex(sw1)+","+hex(sw2)+"] after sending APDU")
            return False, None
        return True, bytes(resp)


    def _select_by_aid(self, aid) -> bool:
        """ Selects an applet by its AID, returns True if successful """
        try:
            apdu = APDU_SELECT + struct.pack("!B", len(aid)) + aid
            resp, sw1, sw2 = self._conn.transmit(list(apdu))
            if (sw1, sw2) != SW_SUCCESS:
                return False
        except:
            return False
        return True
        

    @classmethod
    def list_devices(cls, name: str = "") -> Iterator[CtapPcscDevice] : # type: ignore
        for reader in _list_readers():
            if (name in reader.name):
                try:
                    yield cls(reader.createConnection(), reader.name)
                except Exception as e:
                    pass


#******************************************************************************
# Default class for PCSC connection (PKI & FIDO)

class CtapPcscThalesDevice(CtapPcscDevice, PcscThalesDevice):
    def __init__(self, connection: CardConnection, name: str):
        #super().__init__(connection, name)
        PcscThalesDevice.__init__(self, connection, name, True)
        CtapPcscDevice.__init__(self, connection, name)

    def __repr__(self):
        return f"CtapPcscThalesDevice({self._name}, {self.thales_serial_number})"
    
    @classmethod
    def list_devices(cls, name: str = "") -> Iterator[CtapPcscDevice] :  # type: ignore
        for reader in _list_readers():
            if (name != None) and (name in reader.name):
                try:
                    yield cls(reader.createConnection(), reader.name)
                except  Exception as e:
                    pass    
    
    @classmethod
    def from_pcsc_thales_device(cls, pcsc_thales_device: PcscThalesDevice):
        return cls(pcsc_thales_device._conn, pcsc_thales_device.name)
    
