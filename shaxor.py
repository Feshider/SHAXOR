# MIT License
#
# Copyright (c) 2016 Michal Paulenka <paulenkamichal@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__author__ = "Feshider"

__version__ = 0.9

from argparse import ArgumentParser
from sys import exit, stdout
from hashlib import sha512
from base64 import b64encode, b64decode
from os.path import getsize
from getpass import getpass
from math import sqrt


class SHAXOR:
    argumentParser = ArgumentParser()
    input = None
    output = None
    key = None
    mode = None

    @staticmethod
    def SetArgs():
        SHAXOR.argumentParser.add_argument("-m", "--mode", help="""\"TEXTENC\" - (text) encryption,
                                                                    \"FILE\" - (path to file) encryption/decryption,
                                                                    \"TEXTDEC\" - (text) decryption""",
                                           required=True)
        SHAXOR.argumentParser.add_argument("-i", "--input", help="Text/File for encryption/decryption.", required=True)
        SHAXOR.argumentParser.add_argument("-o", "--output",
                                           help="(path to file) if not set, output is printed to terminal.")

    @staticmethod
    def ParseArgs():
        args = SHAXOR.argumentParser.parse_args()
        SHAXOR.mode = args.mode
        SHAXOR.input = args.input
        SHAXOR.output = args.output

    @staticmethod
    def Decide():
        key1 = getpass(
            "#1 Enter encryption key please: " if SHAXOR.mode == "TEXTENC" or SHAXOR.mode == "FILE" else "#1 Enter decryption key please: ")
        if SHAXOR.mode == "TEXTENC":
            key2 = getpass(
                "#2 Enter encryption key please: " if SHAXOR.mode == "TEXTENC" or SHAXOR.mode == "FILE" else "#2 Enter decryption key please: ")
            if key1 == key2:
                SHAXOR.key = key1
            else:
                print("SHAXOR.py: error: key1 and key2 is different")
                exit()
            SHAXOR.EncText()
        elif SHAXOR.mode == "TEXTDEC":
            SHAXOR.key = key1
            SHAXOR.EncText(decrypt=True)
        elif SHAXOR.mode == "FILE":
            key2 = getpass(
                "#2 Enter encryption key please: ")
            if key1 == key2:
                SHAXOR.key = key1
            else:
                print("SHAXOR.py: error: key1 and key2 is different")
                exit()
            if SHAXOR.output != None:
                SHAXOR.EncFile()
            else:
                print("SHAXOR.py: error: in FILE mode is required argument -o/--output")
                exit()
        else:
            print("SHAXOR.py: error: unknown mode")
            exit()

    @staticmethod
    def UpdateProgress(pr, max):
        pc = int((100 * pr) / float(max))
        stdout.write("[{0}{1}]{2}% {3}B/{4}B\r".format("#" * (pc / 3), " " * (33 - (pc / 3)), pc, pr, max))
        stdout.flush()

    @staticmethod
    def ReadFile():
        try:
            size = getsize(SHAXOR.input)
            with open(SHAXOR.input, "rb") as f:
                while True:
                    chunk = f.read(64)
                    if not chunk:
                        f.close()
                        break
                    SHAXOR.UpdateProgress(f.tell(), size)
                    yield chunk
        except:
            print("SHAXOR.py: error: opening input file occurred some error")
            exit()

    @staticmethod
    def EncFile():
        try:
            o = open(SHAXOR.output, "wb+")
        except:
            print("SHAXOR.py: error: opening output file occurred some error")
            exit()
        for chunk in SHAXOR.ReadFile():
            SHAXOR.key = sha512(SHAXOR.key * int(round(sqrt(getsize(SHAXOR.input)))) if int(round(sqrt(getsize(SHAXOR.input)))) > 1 else 1).digest()
            for i, c in enumerate(chunk):
                o.write(chr(ord(c) ^ ord(SHAXOR.key[i])))
        o.close()

    @staticmethod
    def EncText(decrypt=False):
        if decrypt:
            try:
                SHAXOR.input = b64decode(SHAXOR.input)
            except:
                print("SHAXOR.py: error: decoding text occurred some error, encrypted text is probably damaged")
                exit()
        XOR = ""
        SHAXOR.key = sha512(SHAXOR.key * int(round(sqrt(len(SHAXOR.input)))) if int(round(sqrt(len(SHAXOR.input)))) > 1 else 1).digest()
        for i, c in enumerate(SHAXOR.input):
            XOR += chr(ord(c) ^ ord(SHAXOR.key[i]))
            if i == (len(SHAXOR.key) - 1):
                SHAXOR.key += sha512(SHAXOR.key * int(round(sqrt(len(SHAXOR.input)))) if int(round(sqrt(len(SHAXOR.input)))) > 1 else 1).digest()
        if not decrypt:
            XOR = b64encode(XOR)
        if SHAXOR.output == None:
            print(XOR)
        else:
            try:
                open(SHAXOR.output, "r+").write(XOR)
            except:
                print("SHAXOR.py: error: opening output file occurred some error")


if __name__ == "__main__":
    SHAXOR.SetArgs()
    SHAXOR.ParseArgs()
    SHAXOR.Decide()
