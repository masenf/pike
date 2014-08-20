#
# Copyright (c) 2013, EMC Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Module Name:
#
#        netbios.py
#
# Abstract:
#
#        NETBios frame support
#
# Authors: Brian Koropoff (brian.koropoff@emc.com)
#          Masen Furer (masen.furer@emc.com)
#

import core

class NetbiosOpcode(core.ValueEnum):
    SESSION_MESSAGE           = 0x00
    SESSION_REQUEST           = 0x81
    SESSION_POSITIVE_RESPONSE = 0x82
    SESSION_NEGATIVE_RESPONSE = 0x83
    SESSION_RETARGET_RESPONSE = 0x84
    KEEPALIVE                 = 0x85
NetbiosOpcode.import_items(globals())

class Netbios(core.Frame):

    _nb_request_table = {}
    _nb_response_table = {}
    _nb_protocol_table = {}
    request = core.Register(_nb_request_table, 'opcode')
    response = core.Register(_nb_response_table, 'opcode')
    protocol = core.Register(_nb_protocol_table, 'proto_magic')
    def __init__(self, context=None):
        core.Frame.__init__(self, None, context)
        self.opcode = SESSION_MESSAGE
        self.len = 0
        self._frames = []

    def _children(self):
        return self._frames

    def _encode(self, cur):
        # Frame length (0 for now)
        len_hole = cur.hole.encode_uint32be(0)
        base = cur.copy()

        # encode all the frames
        for frame in self.children:
            frame.encode(cur)

        self.len = cur - base
        # the opcode is 1 byte, BE, the length is 3 bytes, BE
        # so shift opcode left 3 bytes and OR with the length to stuff 
        # both opcode and length into a single 32-bit field
        if len(self._children()) == 1 and hasattr(self._children()[0], "opcode"):
            self.opcode = self._children()[0].opcode
        shift_opcode = self.opcode << 24
        len_hole(self.len | shift_opcode)

    def _decode(self, cur):
        opcode_len = cur.decode_uint32be()
        self.opcode = opcode_len >> 24
        self.len = opcode_len & 0x00FFFFFF
        end = cur + self.len

        with cur.bounded(cur, end):
            if self.opcode != 0:
                if self.opcode in self._response_table:
                    cls = self._nb_response_table[self.opcode]
                    nb_frame = cls(self)
                    with cur.bounded(cur, end):
                        nb_frame.decode(cur)
                raise core.BadPacket("Unknown netbios opcode: {0}".format(self.opcode))
            else:
                # NBSS messages
                while cur.upperbound.offset - cur.offset >= 4:
                    pkt_peek = (cur+0).decode_bytes(4).tostring()
                    if pkt_peek in self._nb_protocol_table:
                        # decode has higher level packet
                        cls = self._nb_protocol_table[pkt_peek]
                        proto_frame = cls(self)
                        proto_frame.decode(cur)
                    else:
                        break       # unknown protocol
                # decode message as generic SessionMessage
                len_remain = cur.upperbound.offset - cur.offset
                if len_remain:
                    nb_frame = SessionMessage(self)
                    nb_frame.decode(cur)

    def append(self, frame):
        self._frames.append(frame)

@Netbios.protocol
class NetbiosProtocol(core.Frame):
    pass

class NetbiosMessage(core.Frame):
     def __init__(self, parent=None):
         core.Frame.__init__(self, parent)
         parent.append(self)
@Netbios.request
class NetbiosRequest(NetbiosMessage):
    pass
@Netbios.response
class NetbiosResponse(NetbiosMessage):
    pass

class NetbiosName(core.Frame):
    def __init__(self, name=None, parent=None):
        core.Frame.__init__(self, parent)
        self.ascii_name = name
        self.suffix = 0
    def encode(self, cur):
        coded_name = []
        ordA = ord('A')     # base value
        labels = self.ascii_name.upper().split(".")
        for ix, label in enumerate(labels):
            # length / padding
            if ix == 0:
                # first label, pad to 32 octets, encoded
                cur.encode_uint8le(0x20)
                if len(label) < 15:
                    label = label + (" " * (15-len(label))) + chr(self.suffix)
                else:
                    label = label[:15] + chr(self.suffix)
                # encoding
                for ch in label:
                    ordch = ord(ch.upper())
                    coded_name.append(ordA + (ordch >> 4))
                    coded_name.append(ordA + (ordch & 0x0F))
                coded_bytes = "".join([chr(o) for o in coded_name])
                cur.encode_bytes(coded_bytes)
            else:       # subsequent labels are simple ASCII, don't ask why
                cur.encode_uint8le(len(label))
                cur.encode_bytes(label)
        # write root label terminator
        cur.encode_uint8le(0x0)
    def decode(self, cur):
        ordA = ord('A')     # base value
        labels = []
        while True:
            length = cur.decode_uint8le()
            if length <= 0:
                break
            if not len(labels):     # first label, decode + pull suffix
                coded_bytes = cur.decode_bytes(length)
                decoded_name = []
                # decoding, 2 octets ==> 1 ASCII char
                for co1, co2 in zip(coded_bytes[::2], coded_bytes[1::2]):
                    decoded_name.append(((co1 - ordA) << 4) + (co2 - ordA))
                self.suffix = decoded_name[-1]
                decoded_name = decoded_name[:-1]
            else:
                decoded_name = cur.decode_bytes(length)
            labels.append("".join([chr(o) for o in decoded_name]).strip())
        self.ascii_name = ".".join(labels)
    def __repr__(self):
        return self.ascii_name

class SessionRequest(NetbiosRequest):
    opcode = SESSION_REQUEST

    def __init__(self, parent=None):
        NetbiosMessage.__init__(self, parent)
        self.called_name = None
        self.calling_name = None
    def encode(self, cur):
        self.called_name.encode(cur)
        self.calling_name.encode(cur)

class PositiveSessionResponse(NetbiosResponse):
    opcode = SESSION_POSITIVE_RESPONSE

    def decode(self, cur):
        pass
class NegativeSessionResponseCode(core.ValueEnum):
    NOT_LISTENING_ON_CALLED_NAME    = 0x80
    NOT_LISTENING_FOR_CALLING_NAME  = 0x81
    CALLED_NAME_NOT_PRESENT         = 0x82
    CALLED_NAME_PRESENT_INSUFFICIENT_RESOURCES = 0x83
    UNSPECIFIED_ERROR               = 0x8F

class NegativeSessionResponse(NetbiosResponse):
    opcode = SESSION_NEGATIVE_RESPONSE

    def __init__(self, parent=None):
        NetbiosMessage.__init__(self, parent)
        self.error_code = None
    def decode(self, cur):
        self.error_code = NegativeSessionResponseCode(cur.decode_uint8le())

class RetargetSessionResponse(NetbiosResponse):
    opcode = SESSION_RETARGET_RESPONSE

    def __init__(self, parent=None):
        NetbiosMessage.__init__(self, parent)
        self.retarget_ip_address = None
        self.port = None
    def decode(self, cur):
        self.retarget_ip_address = cur.decode_uint32be()
        self.port = cur.decode_uint16be()

class SessionKeepAlive(NetbiosResponse, NetbiosRequest):
    opcode = KEEPALIVE

    def encode(self, cur):
        pass
    def decode(self, cur):
        pass

class SessionMessage(NetbiosResponse, NetbiosRequest):
    opcode = SESSION_MESSAGE

    def __init__(self, parent=None):
        NetbiosMessage.__init__(self, parent)
        self.parent = parent
        self.message = None
    def encode(self, cur):
        cur.encode_bytes(self.message)
    def decode(self, cur):
        self.message = cur.decode_bytes(cur.upperbound.offset - cur.offset)
