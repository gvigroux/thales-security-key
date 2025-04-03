from thalessecuritykey.pcsc import PcscThalesDevice
from thalessecuritykey.device import ThalesDevice
from unittest import mock

def test_pcsc_call_cbor():
    device = mock.Mock()
    PcscThalesDevice(device, "Mock")
