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

from typing import Optional
from .const import * 



class ThalesDevice():
    def __init__(self, name : None, has_fido: bool = False):
        self._custom_serial_number  = None
        self._thales_serial_number  = None
        self._pki_version           = None
        self._pki_serial_number     = None
        self._pki_applet            = PkiApplet.UNKNOWN
        self._name                  = name
        self._has_fido              = has_fido
        self._fido_version          = None
        self._is_thales_device      = False
        self._model_name            = None
        self._chip_ref              = None
        self._device_info           = None
        self._form_factor           = FormFactor.UNKNOWN
        self._has_otp               = False

    
    @property
    def is_thales_device(self) -> bool:
        return self._is_thales_device
    
    @property
    def has_fido(self) -> bool:
        return self._has_fido
    
    @has_fido.setter
    def has_fido(self, value):
        self._has_fido = value

    @property
    def has_pki(self) -> bool:
        return self._pki_applet != PkiApplet.UNKNOWN and self._pki_applet != PkiApplet.NONE
    
    @property
    def has_idprime(self) -> bool:
        return self._pki_applet == PkiApplet.IDPRIME or self._pki_applet == PkiApplet.IDPRIME_930 or self._pki_applet == PkiApplet.IDPRIME_940
    
    @property
    def pki_applet(self) -> PkiApplet:
       return self._pki_applet 

    @pki_applet.setter
    def pki_applet(self, value):
       self._pki_applet = value
       if( self.has_idprime ):
           self._is_thales_device = True

    @property
    def has_otp(self) -> bool:
        return self._has_otp

    @property
    def serial_number(self) -> Optional[str]:
        """Serial number of the device."""
        if( self._custom_serial_number != None) :
            return self._custom_serial_number
        if( self._thales_serial_number != None) :
            return self._thales_serial_number
        if( self._pki_serial_number != None) :
            return self._pki_serial_number
        return None

    @serial_number.setter
    def serial_number(self, value):
        if isinstance(value, bytes):
            self._thales_serial_number = self._parse_bytes(value)
        else:
            self._thales_serial_number = value

    @property
    def pki_version(self):
       return self._pki_version 
    
    @pki_version.setter
    def pki_version(self, value: bytes):
        self._pki_version = self._parse_bytes(value)

    @property
    def name(self) -> Optional[str]:
        """Name of device."""
        return self._name
    
    @name.setter
    def name(self, value):
       self._name = value
       
    @property
    def fido_version(self):
        if( self._fido_version == None ) : return "?"
        return self._fido_version

    #@staticmethod
    #def hex(value) -> str:
    #    if isinstance(value, int):
    #        if( value <= 255 ):
    #            return "{:02x} ".format(value).upper()
    #        value = value.to_bytes(4, byteorder='big')
    #    return "".join("{:02x} ".format(x) for x in value).upper()

    def _parse_bytes(self, value : bytes):
        return value.decode("utf-8").strip('\x00')
    
    def _parse_card_manager(self, bytes):
        index=0
        while( index < len(bytes)):
            tag     = bytes[index:index+1]
            length  = bytes[index+1:index+2]
            value   = bytes[index+2:index+2+int.from_bytes(length)]
            index   += 2 + int.from_bytes(length)
            if( tag == TAG_CM_SERIAL_NUMBER): 
                self._thales_serial_number = value.decode("utf-8")
            elif( tag == TAG_CM_PRODUCT_NAME):
                self._name = value.decode("utf-8")
            elif( tag == TAG_CM_MODEL_NAME):
                self._model_name = value.decode("utf-8")
            elif( tag == TAG_CM_MASK): 
                self._chip_ref = value.decode("utf-8")
            elif( tag == TAG_CM_DEVICE_INFO): 
                self._parse_device_info(value)
        # It's a Thales device
        self._is_thales_device  = True 

    def _parse_device_info(self, bytes):
        #length = len(bytes)
        capacity_byte = bytes[0]
        if( capacity_byte&1 ):
            self._pcsc_capable = True
        if( capacity_byte&2 ):
            self._nfc_capable = True
        if( capacity_byte&4 ):
            self._usb_capable = True
        if( capacity_byte&8 ):
            self._bio_capable = True
        if( capacity_byte&32 ):
            self._form_factor = FormFactor.USB_A
        if( capacity_byte&64 ):
            self._form_factor = FormFactor.USB_C
        if( capacity_byte&128 ):
            self._form_factor = FormFactor.SMARTCARD
        else:
            self._token = True
            
        applet_byte = bytes[1]
        if( applet_byte&1 ):
            self.has_pki = True
            self._pki_applet = PkiApplet.IDPRIME_930
        if( applet_byte&2 ):
            self.has_pki = True
            self._pki_applet = PkiApplet.IDPRIME_940
        if( applet_byte&4 ):
            self.has_pki = True
            self._pki_applet = PkiApplet.PIV
        if( applet_byte&8 ):
            self.has_fido = True
        if( applet_byte&16 ):
            self._has_otp = True

        if( self._pki_applet == PkiApplet.UNKNOWN ):
            self._pki_applet = PkiApplet.NONE

    
    def _parse_info_file(self, bytes):
        try:
          if( bytes[0] == 0x01 ):
                index = 1
          elif( bytes[0] == 0x53 ): # 0x50 = TLV
                index = 2 # bytes[1] = full data length

          while( index < len(bytes)):
                tag     = bytes[index:index+4]
                length  = bytes[index+4:index+5]
                value   = bytes[index+5:index+5+int.from_bytes(length)]
                index   += 5 + int.from_bytes(length)
                if( tag == TAG_PRODUCT_NAME):
                    self._name = value.decode("utf-8")
                elif( tag == TAG_MODEL_NAME):
                    self._model_name = value.decode("utf-8")
                elif( tag == TAG_CHIP_REF): 
                    self._chip_ref = value.decode("utf-8")
        except Exception as e:
            print("Error %r", e)

    @property
    def _applets_detail(self):
        out = ""
        if( self.has_fido ):
            out += f"FIDO ({self.fido_version})"
        if( self.has_pki ):
            if( len(out) > 0): out += ", "
            out += f"{self._pki_applet} ({self._pki_version})"
        if( self.has_otp ):
            if( len(out) > 0): out += ", "
            out += f"OTP"
        return out

    def dump(self, full = False) -> Optional[str]:
        """Show all device information."""
        print (self)
        print (f"Is thales:   {self.is_thales_device}")
        print (f"Name:        {self.name}")
        print (f"Serial:      {self.serial_number}")
        print (f"Properties:  {self._applets_detail}" )
        if( full ):
            print (f"Model:       {self._model_name}")
            print (f"Chip:        {self._chip_ref}")
