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

class LargeProcessCount(Signature):
    name = "large_process_count"
    description = "Creates or injects into an excessive number of processes"
    severity = 2
    confidence = 50
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            processcount = len(self.results["behavior"]["processes"])
            if processcount - 1 >= 20:
                self.description = "Creates or injects into a large number of processes"
                self.severity = 3
                return True
            elif processcount - 1 >= 10:
                return True

        return False
