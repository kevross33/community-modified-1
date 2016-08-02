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

class WMICommand(Signature):
    name = "wmi_command"
    description = "Use of a WMI command"
    severity = 2
    confidence = 70
    weight = 0
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.disksize = False
        self.cpucores = False
        self.wmiccmds = []

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if cmdline == "":
                cmdline = self.get_argument(call, "ApplicationName").lower()
        else:
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params

        if "wmic" in cmdline:
            self.wmiccmds.append(cmdline)

        if "wmic" in cmdline and "logicaldisk" in cmdline and "get size" in cmdline:
            self.disksize = True

        if "wmic" in cmdline and "cpu" in cmdline and "numberofcores" in cmdline:
            self.cpucores = True        

    def on_complete(self):
        if self.disksize:
            self.data.append({"checks_disksize" : "Checks disk size potentially to detect sandbox"})
            self.description = "Suspicious use of a WMI command"
            self.severity = 3
            self.weight += 1

        if self.cpucores:
            self.data.append({"checks_cpu_cores" : "Checks for number of CPU cores potentially to detect sandbox"})
            self.description = "Suspicious use of a WMI command"
            self.severity = 3
            self.weight += 1

        if len(self.wmiccmds) > 0:
            for cmdline in self.wmiccmds:
                self.weight += 1
                self.data.append({"wmic_command" : cmdline})

        if self.weight:
            return True
        return False
