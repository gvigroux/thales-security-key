This library is used to communicate with the Thales Security Key.
You can use it to detect the device, get the serial number, the firmware version, etc.
Device class heritate from the [fido2](https://github.com/Yubico/python-fido2) library. So any FIDO2 command can be used.
In case of PCSC Device, you can use the 'has_fido' property to know if the device is a FIDO2 device.

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

## Internal use:

pip install pyscard==2.2.1

python -m build
pip install .\dist\thalessecuritykey-0.0.8-py3-none-any.whl --force-reinstall

py -m pip install --upgrade build
py -m build
py -m pip install --upgrade twine
py -m twine upload --repository testpypi dist/\*
