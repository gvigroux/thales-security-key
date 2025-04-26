This library is used to communicate with Thales Security Key.
You can use it to detect devices, get serial number, firmware version, etc.
Device class heritate from the [fido2](https://github.com/Yubico/python-fido2) library. So any FIDO2 methods can directly be used.
In case of PCSC Device, you can use the 'has_fido_accessible' property to know if the device is a FIDO2 device.

You have to check if the device is a Thales Security Key by using the `is_thales_device` property.

## Installation

```
pip install thalessecuritykey
```

## Usage

```python
from thalessecuritykey import helpers
devices = helpers.scan_devices()
for device in devices:
    print(device)
```

## Example

```python
from thalessecuritykey import helpers
devices = helpers.scan_devices()
for device in devices:
    print(device)
```

