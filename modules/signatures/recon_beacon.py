# Copyright (C) 2015 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class Recon_Beacon(Signature):
    name = "recon_beacon"
    description = "A process performed obfuscation on information about the computer or sent it to a remote location indicative of CnC Traffic/Preperations."
    weight = 2
    severity = 3
    categories = ["network", "recon"]
    authors = ["KillerInstinct", "Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.proclogs = dict()
        self.proclogs_obf = dict()

    filter_apinames = set(["HttpSendRequestA","HttpSendRequestW","HttpOpenRequestA","HttpOpenRequestW","InternetCrackUrlA","InternetCrackUrlW","WSASend","CryptHashData"])

    def on_call(self, call, process):
        # Checks for sending data over network
        if call["api"] == "HttpSendRequestA" or call["api"] == "HttpSendRequestW":
            buf = self.get_argument(call, "PostData")
            if buf:
                if process["process_name"] not in self.proclogs:
                    self.proclogs[process["process_name"]] = set()
                self.proclogs[process["process_name"]].add(buf)

        elif call["api"] == "HttpOpenRequestA" or call["api"] == "HttpOpenRequestW":
            buf = self.get_argument(call, "Path")
            if buf:
                if process["process_name"] not in self.proclogs:
                    self.proclogs[process["process_name"]] = set()
                self.proclogs[process["process_name"]].add(buf)

        elif call["api"] == "InternetCrackUrlA" or call["api"] == "InternetCrackUrlW":
            buf = self.get_argument(call, "Url")
            if buf:
                if process["process_name"] not in self.proclogs:
                    self.proclogs[process["process_name"]] = set()
                self.proclogs[process["process_name"]].add(buf)

        elif call["api"] == "WSASend":
            buf = self.get_argument(call, "Buffer")
            if buf:
                if process["process_name"] not in self.proclogs:
                    self.proclogs[process["process_name"]] = set()
                self.proclogs[process["process_name"]].add(buf)

        # Data preperation likely prior to sending over network in obfsucated form
        elif call["api"] == "CryptHashData":
            buf = self.get_argument(call, "Buffer")
            if buf:
                if process["process_name"] not in self.proclogs_obf:
                    self.proclogs_obf[process["process_name"]] = set()
                self.proclogs_obf[process["process_name"]].add(buf)

    def on_complete(self):
        ret = False
        # should perhaps check for any observed username, not just that of the initial process
        initproc = self.get_initial_process()
        uname = self.get_environ_entry(initproc, "UserName")
        cname = self.get_environ_entry(initproc, "ComputerName")
        if uname:
            uname = uname.lower()
        if cname:
            cname = cname.lower()

        if self.proclogs and cname and uname:
            for proc in self.proclogs:
                for beacon in self.proclogs[proc]:
                    if cname in beacon.lower() or uname in beacon.lower():
                        self.data.append({"Beacon": proc + ": " + beacon})
                        ret = True

        if self.proclogs_obf and cname and uname:
            for proc in self.proclogs_obf:
                for beacon in self.proclogs_obf[proc]:
                    if cname in beacon.lower() or uname in beacon.lower():
                        self.data.append({"Data Being Obfuscated": proc + ": " + beacon})
                        ret = True

        return ret
