# Copyright 2014, 2015 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import struct
import hashlib
import hmac
from io import BytesIO
###
from pyhdb.protocol.segments import RequestSegment
from pyhdb.protocol.constants import message_types
from pyhdb.protocol.parts import Authentication, Fields
from pyhdb.protocol.message import RequestMessage
from pyhdb.compat import iter_range

CLIENT_PROOF_SIZE = 32
CLIENT_KEY_SIZE = 64


class AuthManager(object):

    def __init__(self, connection, user, password, auth):
        self.connection = connection
        self.user = user
        self.password = password

        if auth == 'pbkdf2':
            self.method = b"SCRAMPBKDF2SHA256"
        else:
            self.method = b"SCRAMSHA256"
        self.client_key = os.urandom(CLIENT_KEY_SIZE)
        self.client_proof = None

    def perform_handshake(self):
        request = RequestMessage.new(
            self.connection,
            RequestSegment(
                message_types.AUTHENTICATE,
                Authentication(self.user, {self.method: self.client_key})
            )
        )
        response = self.connection.send_request(request)

        auth_part = response.segments[0].parts[0]
        if self.method not in auth_part.methods:
            raise Exception(
                "Only unknown authentication methods available: %s" %
                b",".join(auth_part.methods.keys())
            )

        count = None
        if self.method == b"SCRAMSHA256":
            salt, server_key = Fields.unpack_data(
                BytesIO(auth_part.methods[self.method])
            )
        else:
            salt, server_key, cnt = Fields.unpack_data(
                BytesIO(auth_part.methods[self.method])
            )
            count = struct.unpack('>I', cnt)

        self.client_proof = self.calculate_client_proof([salt], server_key, count[0])

        return Authentication(self.user, {self.method: self.client_proof})

    def calculate_client_proof(self, salts, server_key, count):
        proof = b"\x00"
        proof += struct.pack('b', len(salts))

        for salt in salts:
            proof += struct.pack('b', CLIENT_PROOF_SIZE)
            proof += self.scramble_salt(salt, server_key, count)

        return proof

    def scramble_salt(self, salt, server_key, count):
        msg = salt + server_key + self.client_key

        if self.method == b"SCRAMSHA256":
            key_salt = hmac.new(self.password.encode('utf-8'), salt, hashlib.sha256).digest()
        elif self.method == b"SCRAMPBKDF2SHA256":
            key_salt = hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), salt, count)
        else:
            raise Exception(f"Non implemented authentication method: {self.method}")

        key = hashlib.sha256(key_salt).digest()
        key_hash = hashlib.sha256(key).digest()

        sig = hmac.new(
            key_hash, msg, hashlib.sha256
        ).digest()
        
        return self._xor(sig, key)

    @staticmethod
    def _xor(a, b):
        a = bytearray(a)
        b = bytearray(b)
        result = bytearray(len(a))
        for i in iter_range(len(a)):
            result[i] += a[i] ^ b[i]
        return bytes(result)
