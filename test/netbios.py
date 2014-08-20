#
# Copyright (C) EMC Corporation.  All rights reserved.
#
# Module Name:
#
#       netbios.py
#
# Abstract:
#
#       Basic netbios session tests
#
# Authors: Masen Furer (masen.furer@emc.com)
#

from pike.test import PikeTest
import pike.model as model
import pike.netbios as netbios
import sys
import time

class TestNetbios(PikeTest):
    def _test_bogus_opcode(self):       # not currently working
        conn = model.NBConnection(self.option("PIKE_SERVER"))
        nb_req = netbios.Netbios()
        ka_req = netbios.SessionKeepAlive(nb_req)
        ka_req.opcode = 0x10
        result = conn.transceive(nb_req)[0]
        conn.close()

    def test_keepalive(self):
        conn = model.NBConnection(self.option("PIKE_SERVER"))
        # now send some keepalives
        for ix in xrange(10):
            nb_req = netbios.Netbios()
            ka_req = netbios.SessionKeepAlive(nb_req)
            result = conn.transceive(nb_req)[0]
            self.assertIsInstance(result, netbios.Netbios)
            self.assertIsInstance(result[0], netbios.SessionKeepAlive)
            sys.stderr.write(".")
            time.sleep(2)
        conn.close()

    def test_session_request(self):
        conn = model.NBConnection(self.option("PIKE_SERVER"))
        nb_request = netbios.Netbios()
        called_name = netbios.NetbiosName(self.option("PIKE_NETBIOS_NAME",
                                          self.option("PIKE_SERVER", "TARGET")))
        called_name.suffix = 0x20
        calling_name = netbios.NetbiosName("PIKE_CLIENT")
        calling_name.suffix = 0
        session_req = netbios.SessionRequest(nb_request)
        session_req.called_name = called_name
        session_req.calling_name = calling_name

        result = conn.transceive(nb_request)[0]
        self.assertIsInstance(result, netbios.Netbios)
        self.assertIsInstance(result[0], netbios.PositiveSessionResponse)
        sys.stderr.write("S! ")

        conn.close()

if __name__ == "__main__":
    import pike_script
