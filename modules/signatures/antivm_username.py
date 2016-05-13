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

class AntiVMUsernameQuery(Signature):
    name = "antivm_queries_username"
    description = "Queries for the logged in username"
    severity = 1
    categories = ["AntiVM"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["GetUserNameA","GetUserNameW","GetUserNameExA","GetUserNameExW"])

    def on_call(self, call, process):
        return True
