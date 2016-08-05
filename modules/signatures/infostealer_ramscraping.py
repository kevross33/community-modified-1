# Copyright (C) 2016 Kevin Ross
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

class InfoStealerRamScraping(Signature):
    name = "infostealer_ramscraping"
    description = "Appears to be performing RAM scraping to retrieve information from the memory of another process"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.readcount = 0
        self.readprocs = dict()
        self.lastpid = ""
        self.lasthandle = ""
        self.lastprocess = ""

    filter_apinames = set(["Process32NextW", "NtOpenProcess", "ReadProcessMemory"])

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            pid = self.get_argument(call, "ProcessId")
            pname = self.get_argument(call, "ProcessName")
            self.lastpid = pid
            self.lastprocess = pname

        if call["api"] == "NtOpenProcess" and self.lastprocess != "" and self.lastpid != "":
            pid = self.get_argument(call, "ProcessIdentifier")
            handle = self.get_argument(call, "ProcessHandle")
            if pid == self.lastpid:
                self.lasthandle = handle       

        elif call["api"] == "ReadProcessMemory" and self.lasthandle != "":
            handle = self.get_argument(call, "ProcessHandle")
            buf = self.get_argument(call, "Buffer")
            if handle != "0xffffffff" and handle == self.lasthandle and len(buf) > 0:
                pname = self.lastprocess
                if pname not in self.readprocs:
                    self.readprocs[pname] = 0
                self.readprocs[pname] += 1 

    def on_complete(self):
        for pname, total in self.readprocs.items():
            if total > 50:
                self.data.append({"scraped_process": pname})
                return True

        return False
