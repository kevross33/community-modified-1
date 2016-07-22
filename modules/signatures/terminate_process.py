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

class TerminateProcess(Signature):
    name = "terminate_process"
    description = "A process was terminated in a suspicious manner"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cmdline = []
        self.terminated = []

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW","NtTerminateProcess"])

    def on_call(self, call, process):
        if call["api"] == "NtTerminateProcess":
            handle = self.get_argument(call, "ProcessHandle")
            if handle != "0x00000000" and handle != "0xffffffff":
                procname = self.get_name_from_pid(handle)
                if procname not in self.terminated:
                    self.terminated.append(procname)
        elif call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "taskkill" in cmdline:
                self.cmdline.append(cmdline)
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params
            if "taskkill" in cmdline:
                self.cmdline.append(cmdline)

    def on_complete(self):
        ret = False

        if len(self.terminated) > 0:
            for terminated in self.terminated:
                self.data.append({"terminated_another_process" : terminated})
                ret = True

        if len(self.cmdline) > 0:
            for cmdline in self.cmdline:
                self.data.append({"termination_cmdline" : cmdline})
                ret = True

        return ret
