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
from .const import TAG_CHIP_REF, TAG_MODEL_NAME, TAG_NVM, TAG_PRODUCT_NAME, PkiApplet




class ThalesDevice():
    def __init__(self, name : None, has_fido: bool = False):
        self._custom_serial_number  = None
        self._thales_serial_number  = None
        self._pki_version           = None
        self._pki_serial_number     = None
        self._pki_applet            = PkiApplet.NONE
        self._name                  = name
        self._has_fido              = has_fido
        self._fido_version          = None
        self._is_thales_device      = False
        self._nvm                   = None
        self._model_name            = None
        self._chip_ref              = None

    
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
    def pki_applet(self) -> PkiApplet:
       return self._pki_applet 

    @pki_applet.setter
    def pki_applet(self, value):
       self._pki_applet = value

    @property
    def thales_serial_number(self) -> Optional[str]:
        """Serial number of the device."""
        if( self._custom_serial_number != None) :
            return self._custom_serial_number
        if( self._thales_serial_number != None) :
            return self._thales_serial_number
        if( self._pki_serial_number != None) :
            return self._pki_serial_number
        return None
    
    @thales_serial_number.setter
    def thales_serial_number(self, value: bytes):
        self._thales_serial_number = self._parse_bytes(value)

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

    #@staticmethod
    #def hex(value) -> str:
    #    if isinstance(value, int):
    #        if( value <= 255 ):
    #            return "{:02x} ".format(value).upper()
    #        value = value.to_bytes(4, byteorder='big')
    #    return "".join("{:02x} ".format(x) for x in value).upper()

    def _parse_bytes(self, value : bytes):
        return value.decode("utf-8").split('\x00', 1)[0]
    
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
                if( tag == TAG_NVM): 
                    self._nvm = int.from_bytes(value)
                elif( tag == TAG_PRODUCT_NAME):
                    self._name = value.decode("utf-8")
                elif( tag == TAG_MODEL_NAME):
                    self._model_name = value.decode("utf-8")
                elif( tag == TAG_CHIP_REF): 
                    self._chip_ref = value.decode("utf-8")
        except Exception as e:
            print("Error %r", e)

    def dump(self, full = True) -> Optional[str]:
        """Show all device information."""
        print (self)
        print (f"Is thales:   {self.is_thales_device}")
        print (f"Name:        {self.name}")
        print (f"Has FIDO:    {self.has_fido}")
        print (f"FIDO Version:{self._fido_version}")
        print (f"Has PKI:     {self.has_pki}")
        if( full ):
            print (f"Custom S/N:  {self._custom_serial_number}")
            print (f"Thales S/N:  {self._thales_serial_number}")
            print (f"PKI S/N:     {self._pki_serial_number}")
        else:
            print (f"Thales S/N:  {self.thales_serial_number}")
        print (f"PKI Applet:  {self._pki_applet}")
        print (f"PKI Version: {self._pki_version}")
        if( full ):
            print (f"NVM :        {self._nvm}")
            print (f"Model:       {self._model_name}")
            print (f"Chip:        {self._chip_ref}")
