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

from enum import Enum
from .atr import ATR

class PkiApplet(Enum):
    UNKNOWN = -1
    NONE = 0
    IDPRIME_930 = 1
    IDPRIME_940 = 2
    PIV = 3

# List of ATRs for Thales NFC devices
ATRs = [
  ATR("eToken Fusion",      0x3b8f800180318065b00000000012017882900000,             0xFFFFFFFFFFFFFFFFF000000000FFFFFFFFFFFF00 ), #PIV, #FIPS
  ATR("eToken Fusion CC",   0x3bff9600008131fe4380318065b0855956fb12017882900088,   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
  ATR("eToken Fusion FIPS", 0x3bff9600008131fe4380318065b0846566fb12017882900085,   0xFFFF00FFFFFFFF00FFFFFFFFFF00000000FFFFFFFFFF00), #5300 ATR
]

# USB Vendor ID for Thales Security Key
thales_vendor_id  = 0x08E6

# Applet IDs
AID_PIV           = b"\xa0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00"
AID_PIV_ADMIN     = b"\xa0\x00\x00\x03\x08\x00\x00\x10\x00\x02\x00"
AID_IDPRIME       = b"\xa0\x00\x00\x00\x18\x80\x00\x00\x00\x06\x62"
AID_IDPRIME_930   = b"\xa0\x00\x00\x00\x18\x80\x00\x00\x00\x41\x51"
AID_IDPRIME_940   = b"\xa0\x00\x00\x00\x18\x80\x00\x00\x00\x40\x51"
AID_CARD_MANAGER  = b"\x00\xA4\x04\x00\x00"

# Standard APDU
APDU_SELECT       = b"\x00\xA4\x04\x00"
APDU_SELECT_FILE  = b"\x00\xA4\x00\x0C"
APDU_READ_BINARY  = b"\x00\xB0\x00\x00"
APDU_GET_SN       = b"\x80\xCA\x01\x04\x00"
APDU_GET_DETAILS  = b"\x00\xCA\x01\x05\x00"
APDU_GET_CONTAINER= b"\x00\xCB\x3F\xFF\x05\x5C"

APDU_IDP_GET_DATA   = b"\x00\xCA"
APDU_PIV_GET_DATA   = b"\x80\xCB"

# Thales Security Key Info File TAGs
TAG_NVM           = b"\xFF\xFF\x00\x06"
TAG_PRODUCT_NAME  = b"\x80\x00\x11\x01"
TAG_MODEL_NAME    = b"\x80\x00\x11\x02"
TAG_CHIP_REF      = b"\x80\x00\x11\x59"

# Thales Security Key Info File TAGs
TAG_CM_SERIAL_NUMBER   = b"\xA1"
TAG_CM_PRODUCT_NAME    = b"\xA2"
TAG_CM_MODEL_NAME      = b"\xA3"
TAG_CM_MASK            = b"\xA4"
TAG_CM_DEVICE_INFO     = b"\xA5"

