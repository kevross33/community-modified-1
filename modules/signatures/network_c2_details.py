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

class NetworkC2Details(Signature):
    name = "network_c2_details"
    description = "Queried details from the computer were then used in a network or crypto API call indicative of command and control communications/preperations"
    severity = 3
    confidence = 20
    categories = ["infostealer","c2","network"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.computerdetails = []
        self.cnc = False

    filter_apinames = set(["GetComputerNameA","GetUserNameA","GetComputerNameW","GetUserNameW","CryptHashData","HttpSendRequestW","HttpOpenRequestW","InternetCrackUrlW","WSASend"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        # Here we check for interesting bits of data which may be queried and used in cnc for computer identification
        api = call["api"]
        if api == "GetComputerNameA" or api == "GetComputerNameW":
            compname = self.get_argument(call, "ComputerName")
            if compname:
                self.computerdetails.append(compname)

        elif api == "GetUserNameA" or api == "GetUserNameW":
            username = self.get_argument(call, "UserName")
            if username:
                self.computerdetails.append(username)

        elif api == "CryptHashData":
            buff = self.get_argument(call, "Buffer")
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.data.append({"C2_Preperation_CryptoHashData": buff})
                    self.cnc = True

        elif api == "HttpSendRequestW":
            buff = self.get_argument(call, "PostData")
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.data.append({"C2_HttpSendRequestW": buff})
                    self.cnc = True

        elif api == "HttpOpenRequestW":
            buff = self.get_argument(call, "Path")
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.data.append({"C2_HttpOpenRequestW": buff})
                    self.cnc = True

        elif api == "InternetCrackUrlW":
            buff = self.get_argument(call, "Url")
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.data.append({"C2_InternetCrackUrlW": buff})
                    self.cnc = True

        elif api == "WSASend":
            buff = self.get_argument(call, "Buffer")
            for compdetails in self.computerdetails:
                if compdetails in buff:
                    self.data.append({"C2_WSASend": buff})
                    self.cnc = True

    def on_complete(self):
        if self.cnc:
            return True

        return False
