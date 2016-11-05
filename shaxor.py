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

#########################################################
#                                                       #
#       DON'T USE SAME ENCRYPTION KEY TWO TIMES!!!      #
#                                                       #
#########################################################

__author__ = "Feshider"

__version__ = "0.9.1"

from argparse import ArgumentParser
from sys import exit, stdout
from hashlib import sha512
from base64 import b64encode, b64decode
from os.path import getsize
from getpass import getpass
from time import time


class SHAXOR:
    argumentParser = ArgumentParser()
    inp = None
    output = None
    key = None
    mode = None
    time_temp = 1
    chunk_size = 8192

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
        SHAXOR.inp = args.input
        SHAXOR.output = args.output

    @staticmethod
    def GetKeys(count, mode=0):
        keys = []
        if mode == 0:
            word = "encrytion/decryption"
        elif mode == 1:
            word = "encryption"
        elif mode == 2:
            word = "decryption"
        for i in range(1, count+1):
            keys.append(getpass("{0}# Enter {1} key please: ".format(i, word)))
        if len(keys) == 2:
            if keys[0] == keys[1]:
                SHAXOR.key = keys[0]
            else:
                print("SHAXOR.py: error: keys is different.")
                exit()
        else:
            SHAXOR.key = keys[0]

    @staticmethod
    def Decide():
        if SHAXOR.mode == "TEXTENC":
            SHAXOR.GetKeys(2, 1)
            SHAXOR.EncText()
        elif SHAXOR.mode == "TEXTDEC":
            SHAXOR.GetKeys(1, 2)
            SHAXOR.EncText(decrypt=True)
        elif SHAXOR.mode == "FILE":
            SHAXOR.GetKeys(2, 0)
            if SHAXOR.output != None:
                SHAXOR.EncFile()
            else:
                print("SHAXOR.py: error: in FILE mode is required argument -o/--output")
                exit()
        else:
            print("SHAXOR.py: error: unknown mode")
            exit()

    @staticmethod
    def sizeof_fmt(num):  # Thanks to Fred Cirera.
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return "%3.1f%s" % (num, x)
            num /= 1024.0

    @staticmethod
    def UpdateProgress(pr, max):
        speed = int(SHAXOR.chunk_size*(1/float(time()-SHAXOR.time_temp)))
        pc = int((100 * pr) / float(max))
        stdout.write("[{0}{1}]{2}% {3}/{4}  {5}/s\r".format("#" * (pc / 4), " " * (25 - (pc / 4)), pc,
                                                          SHAXOR.sizeof_fmt(pr), SHAXOR.sizeof_fmt(max),
                                                          SHAXOR.sizeof_fmt(speed)))
        stdout.flush()

    @staticmethod
    def ReadFile():
        try:
            size = getsize(SHAXOR.inp)
            with open(SHAXOR.inp, "rb") as f:
                while True:
                    SHAXOR.time_temp = time()
                    chunk = f.read(SHAXOR.chunk_size)
                    if not chunk:
                        f.close()
                        break
                    yield chunk
                    SHAXOR.UpdateProgress(f.tell(), size)
        except IOError:
            print("SHAXOR.py: error: opening input file occurred some error")
            exit()

    @staticmethod
    def Factor(hs):
        sum = 0
        for i in range(0, 64, 8):
            sum += ord(hs[i])
        return sum

    @staticmethod
    def EncFile():
        try:
            o = open(SHAXOR.output, "wb+")
        except:
            print("SHAXOR.py: error: opening output file occurred some error")
            exit()
        key = sha512(SHAXOR.key).digest()
        for chunk in SHAXOR.ReadFile():
            SHAXOR.key = ""
            for i in range(SHAXOR.chunk_size/64):
                factor = SHAXOR.Factor(key)
                hs = sha512(key *  (factor if factor > 0 else 1)).digest()
                SHAXOR.key += hs
                key = hs
            for i, c in enumerate(chunk):
                o.write(chr(ord(c) ^ ord(SHAXOR.key[i])))
        o.close()

    @staticmethod
    def EncText(decrypt=False):
        if decrypt:
            try:
                SHAXOR.inp = b64decode(SHAXOR.inp)
            except:
                print("SHAXOR.py: error: decoding text occurred some error, encrypted text is probably damaged")
                exit()
        XOR = ""
        SHAXOR.key = sha512(SHAXOR.key).digest()
        factor = SHAXOR.Factor(SHAXOR.key)
        SHAXOR.key = sha512(SHAXOR.key * (factor if factor > 0 else 1)).digest()
        for i, c in enumerate(SHAXOR.inp):
            XOR += chr(ord(c) ^ ord(SHAXOR.key[i]))
            if i == (len(SHAXOR.key) - 1):
                factor = SHAXOR.Factor(SHAXOR.key)
                SHAXOR.key += sha512(SHAXOR.key * (factor if factor > 0 else 1)).digest()
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
