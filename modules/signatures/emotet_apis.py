# Copyright (C) 2017 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

class Emotet_APIs(Signature):
    name = "emotet_behavior"
    description = "Exhibits behavior characteristic of Emotet/Geodo Malware"
    weight = 3
    severity = 3
    categories = ["infostealer", "banker"]
    families = ["Emotet"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compname = []
        self.processlist = []
        self.c2 = []
        self.isemotet = False
        self.lasthandle = str()
        self.ip = str()

    filter_apinames = set(["GetComputerNameW", "Process32NextW", "CryptEncrypt", "InternetConnectW", "HttpOpenRequestW", "HttpSendRequestW"])

    def on_call(self, call, process):
        if call["api"] == "GetComputerNameW":
            if call["status"]:
                compname = self.get_argument(call, "ComputerName")
                if compname not in self.compname:
                    self.compname.append(compname)

        elif call["api"] == "Process32NextW":
            if call["status"]:
                procname = self.get_argument(call, "ProcessName")
                if procname not in self.processlist:
                    self.processlist.append(procname)

        elif call["api"] == "CryptEncrypt":
            if call["status"]:
                buf = self.get_argument(call, "Buffer")
                if "[System Process]" in buf:
                    for compname in self.compname:
                        if compname in buf:
                            count = 0
                            for proc in self.processlist:
                                if proc in buf:
                                    count += 1
                            if count > 5:
                                self.emotet = True

        elif call["api"] == "InternetConnectW" and self.emotet:
            ip = self.get_argument(call, "ServerName")
            if ip not in self.c2:
                self.ip = ip
                self.lasthandle = call["return"]

        elif call["api"] == "HttpOpenRequestW" and self.emotet:
            handle = self.get_argument(call, "InternetHandle")
            if handle == self.lasthandle:
                self.lasthandle = call["return"]

        elif call["api"] == "HttpSendRequestW" and self.emotet:
            handle = self.get_argument(call, "RequestHandle")
            if handle == self.lasthandle:
                headers = self.get_argument(call, "Headers")
                if re.match(r"^Cookie\:\ [A-Za-z0-9]{3,4}=(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$", headers):
                    self.data.append({"C2": self.ip})
                    self.c2.append(self.ip)

    def on_complete(self):
        if self.emotet:
            return True
