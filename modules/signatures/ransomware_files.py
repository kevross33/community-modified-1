# Copyright (C) 2015 KillerInstinct, Optiv, Inc. (brad.spengler@optiv.com)
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

class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Creates a known ransomware decryption instruction / key file."
    weight = 3
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct"]
    minimum = "1.2"

    def run(self):
        # List of tuples with a regex pattern for the file name and a list of
        # family names correlating to the ransomware. If the family is unknown
        # just use [""].
        file_list = [
            (".*\\\\help_decrypt\.html$", ["CryptoWall"]),
            (".*\\\\decrypt_instruction\.html$", ["CryptoWall"]),
            (".*\\\\help_your_files\.png$", ["CryptoWall"]),
            (".*\\\\decrypt_instructions\.txt$", ["CryptoLocker"]),
            (".*\\\\vault\.(key|txt)$", ["CrypVault"]),
            (".*\\\\!Decrypt-All-Files.*\.(txt|bmp)$", ["CTB-Locker"]),
            (".*\\\\help_restore_files\.txt$", ["AlphaCrypt", "TeslaCrypt"]),
            (".*\\\\help_to_save_files\.(txt|bmp)$", ["AlphaCrypt", "TeslaCrypt"]),
            (".*\\\\recovery_(file|key)\.txt$", ["AlphaCrypt"]),
            (".*\\\\restore_files_.*\.(txt|html)$", ["AlphaCrypt", "TeslaCrypt"]),
            (".*\\\\howto_restore_files.*\.(txt|html)$", ["AlphaCrypt", "TeslaCrypt"]),
            (".*\\\\YOUR_FILES_ARE_ENCRYPTED\.HTML$", ["Chimera"]),
            (".*\\\\_?how_recover.*\.(txt|html)$", ["AlphaCrypt"]),
            (".*\\\\cl_data.*\.bak$", ["WinPlock"]),
            (".*\\\\READ\ ME\ FOR\ DECRYPT\.txt$", ["Fakben"]),
            (".*\\\\YOUR_FILES.url$", ["Radamant"]),
            (".*\\\\_How\ to\ decrypt\ LeChiffre\ files\.html$", ["LeChiffre"]),
            (".*\\\\cryptinfo\.txt$", ["DMALocker"]),
            (".*\\\\HELP_RECOVER_instructions\+.*\.(txt|html)$", ["TeslaCrypt"]),
            (".*\\\\README_DECRYPT_HYDRA_ID_.*(\.txt|\.jpg)$", ["HydraCrypt"]),
            (".*\\\\_Locky_recover_instructions.txt$", ["Locky"]),
        ]

        for ioc in file_list:
            if self.check_write_file(pattern=ioc[0], regex=True):
                if ioc[1] != "":
                    self.families = ioc[1]
                    self.description = ("Creates a known {0} ransomware "
                                        "decryption instruction / key file."
                                        "".format("/".join(ioc[1])))
                return True

        return False
