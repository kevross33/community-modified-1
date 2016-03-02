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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class RansomwareLocky(Signature):
    name = "ransomware_locky"
    description = "Exhibits behavior characteristic of Locky ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["locky"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptohttp = False
        self.cryptedbody = []
        self.httpcnc = False
        self.cncs = []
        self.process = []
     
    filter_apinames = set(["CryptHashData","InternetCrackUrlA"])

    def on_call(self, call, process):

        # Checking for and extracting C2 details
        pname = process["process_name"].lower()
        if call["api"] == "CryptHashData":
            cryptbody = re.compile("^id=[A-F0-9]{16}&act=(getkey|gettext|stats).*")
            buf = self.get_argument(call, "Buffer")
            if cryptbody.match(buf):
                if self.cryptedbody.count(buf) == 0:
                    self.cryptedbody.append(buf)
                if self.process.count(pname) == 0:
                    self.process.append(pname)
                self.cryptohttp = True

        if call["api"] == "InternetCrackUrlA":
            buf = self.get_argument(call, "Url")
            if "/main.php" in buf and pname in self.process:
                if self.cncs.count(buf) == 0:
                    self.cncs.append(buf)
                self.httpcnc = True

    def on_complete(self):
        ret = False

        keys = [".*\\\\\Software\\\\(Wow6432Node\\\\)?Locky$",".*\\\\\Software\\\\(Wow6432Node\\\\)?Locky\\\\id$",".*\\\\\Software\\\\(Wow6432Node\\\\)?Locky\\\\pubkey$",".*\\\\\Software\\\\(Wow6432Node\\\\)?Locky\\\\paytext$"]
        extensions = [".*\.locky$"]

        for key in keys:
            matches = self.check_write_key(pattern=key, regex=True, all=True)
            if matches:
                ret = True

        for extension in extensions:
            results = self.check_write_file(pattern=extension, regex=True, all=True)
            if results and len(results) > 15:
                ret = True

        # Append CnCs. However not marked as true as not a strong enough indicator on its own so will only appear if other indicators show sample to be locky.
        if self.httpcnc:
            for cnc in self.cncs:
                self.data.append({"cnc_http" : cnc})

        if self.cryptohttp:
            for body in self.cryptedbody:
                self.data.append({"cnc_http_post (crypted)" : body})
            ret = True

        return ret
