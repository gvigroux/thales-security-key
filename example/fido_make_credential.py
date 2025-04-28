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

from thalessecuritykey import helpers
from fido2.client import Fido2Client, UserInteraction
from fido2.server import Fido2Server

full_rp = "http://localhost:3000"
json_rp = "localhost"


for _ in iter(int, 1):
    print("\33[93mWaiting device...\33[0m")
    devices   = helpers.scan_devices(True)
    print("\33[93mFound [%d] device(s)...\33[0m" % len(devices))

    for device in devices:

        # Create client
        client = Fido2Client(device, full_rp)

        # Create server
        server = Fido2Server({"id": json_rp, "name": "Thales"}, attestation="direct")
        user = {"id": b"user_id", "name": "User"}
        create_options, state = server.register_begin(user, user_verification="discouraged", authenticator_attachment="cross-platform")
        publicKeyOptions = create_options["publicKey"]

        # Make credential
        result = client.make_credential(publicKeyOptions)                            

        print("")
    input("\33[93mPress Enter to continue...\33[0m")


