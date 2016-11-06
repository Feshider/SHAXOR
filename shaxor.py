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
from os import path, remove
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
    def set_args():
        SHAXOR.argumentParser.add_argument("-m", "--mode", help="""\"TE\" - (text) Text Encryption mode,
                                                                    \"F\" - (path to file) File encryption/decryption mode,
                                                                    \"TD\" - (text) Text Decryption mode""",
                                           required=True)
        SHAXOR.argumentParser.add_argument("-i", "--input", help="(text/file) for encryption/decryption", required=True)
        SHAXOR.argumentParser.add_argument("-o", "--output",
                                           help="(path to file) if not set, output is printed to terminal")

    @staticmethod
    def parse_args():
        args = SHAXOR.argumentParser.parse_args()
        SHAXOR.mode = args.mode
        SHAXOR.inp = args.input
        SHAXOR.output = args.output

    @staticmethod
    def show_banner():
        banner = """\
_____________  ____________  ________________
__  ___/__  / / /__    |_  |/ /_  __ \__  __ \*
_____ \__  /_/ /__  /| |_    /_  / / /_  /_/ /*
____/ /_  __  / _  ___ |    | / /_/ /_  _, _/*
/____/ /_/ /_/  /_/  |_/_/|_| \____/ /_/ |_|*\n"""
        print(banner)
        print(" DON'T USE SAME KEY TWO OR MORE TIMES!!!\n")

    @staticmethod
    def get_keys(mode=None, two=True):
        if mode == 1:
            word = "encryption"
        elif mode == 2:
            word = "decryption"
        else:
            word = "encrytion/decryption"

        key1 = getpass("1# Enter {0} key please: ".format(word))
        if two:
            key2 = getpass("2# Enter {0} key please: ".format(word))
            if key1 == key2:
                SHAXOR.key = key1
                print()
                return
            else:
                print("shaxor.py: error: keys is different.")
                exit()
        else:
            SHAXOR.key = key1
        print()

    @staticmethod
    def decide():
        if SHAXOR.mode == "TE":
            SHAXOR.get_keys(mode=1)
            SHAXOR.enc_text()
            return
        elif SHAXOR.mode == "TD":
            SHAXOR.get_keys(mode=2, two=False)
            SHAXOR.enc_text(decrypt=True)
            return
        elif SHAXOR.mode == "F":
            SHAXOR.get_keys()
            if SHAXOR.output is not None:
                SHAXOR.enc_file()
                return
            else:
                print("shaxor.py: error: in FILE mode is required argument -o/--output")
                exit()
        else:
            print("shaxor.py: error: unknown mode")
            exit()

    @staticmethod
    def sizeof_fmt(num):  # Thanks to Fred Cirera.
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return "%3.1f%s" % (num, x)
            num /= 1024.0

    @staticmethod
    def update_progress(pr, max):
        speed = int(SHAXOR.chunk_size*(1/float(time()-SHAXOR.time_temp)))
        pc = int((100 * pr) / float(max))
        stdout.write("[{0}{1}]{2}% {3}/{4}  {5}/s\r".format("#" * (pc / 4), " " * (25 - (pc / 4)), pc,
                                                          SHAXOR.sizeof_fmt(pr), SHAXOR.sizeof_fmt(max),
                                                          SHAXOR.sizeof_fmt(speed)))
        stdout.flush()

    @staticmethod
    def read_file(indicate):
        try:
            size = path.getsize(SHAXOR.inp)
            with open(SHAXOR.inp, "rb") as f:
                while True:
                    SHAXOR.time_temp = time()
                    chunk = f.read(SHAXOR.chunk_size)
                    if not chunk:
                        f.close()
                        break
                    yield chunk
                    if indicate:
                        SHAXOR.update_progress(f.tell(), size)
        except:
            print("shaxor.py: error: opening input file occurred some error")
            exit()

    @staticmethod
    def factor(hs):
        sum = 0
        for i in range(0, 64, 8):
            sum += ord(hs[i])
        return sum

    @staticmethod
    def enc_file(indicate=True):
        try:
            o = open(SHAXOR.output, "wb+")
        except:
            print("shaxor.py: error: opening output file occurred some error")
            exit()
        key = sha512(SHAXOR.key).digest()
        for chunk in SHAXOR.read_file(indicate=indicate):
            SHAXOR.key = ""
            for i in range(SHAXOR.chunk_size/64):
                factor = SHAXOR.factor(key)
                hs = sha512(key * (factor if factor > 0 else 1)).digest()
                SHAXOR.key += hs
                key = hs
            for i, c in enumerate(chunk):
                o.write(chr(ord(c) ^ ord(SHAXOR.key[i])))
        o.close()

    @staticmethod
    def enc_text(decrypt=False, unit_test=False):
        if decrypt:
            try:
                SHAXOR.inp = b64decode(SHAXOR.inp)
            except:
                print("shaxor.py: error: decoding text occurred some error, encrypted text is probably damaged")
                exit()
        XOR = ""
        SHAXOR.key = sha512(SHAXOR.key).digest()
        factor = SHAXOR.factor(SHAXOR.key)
        SHAXOR.key = sha512(SHAXOR.key * (factor if factor > 0 else 1)).digest()
        for i, c in enumerate(SHAXOR.inp):
            if i > 63:
                i %= 64
            XOR += chr(ord(c) ^ ord(SHAXOR.key[i]))
            if i == (len(SHAXOR.key) - 1):
                factor = SHAXOR.factor(SHAXOR.key)
                SHAXOR.key = sha512(SHAXOR.key * (factor if factor > 0 else 1)).digest()
        if not decrypt:
            XOR = b64encode(XOR)
        if unit_test:
            return XOR
        if SHAXOR.output is None:
            print(XOR)
        else:
            try:
                open(SHAXOR.output, "r+").write(XOR)
            except:
                print("shaxor.py: error: opening output file occurred some error")


class UnitTest:
    test_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    @staticmethod
    def text_test():
        SHAXOR.inp, SHAXOR.key = (UnitTest.test_string * 100), UnitTest.test_string
        SHAXOR.inp = SHAXOR.enc_text(unit_test=True)
        SHAXOR.key = UnitTest.test_string
        if (UnitTest.test_string * 100) != SHAXOR.enc_text(unit_test=True, decrypt=True):
            print("shaxor.py: error: Text encryption unit test error")
            exit()
        return True

    @staticmethod
    def file_test():
        if path.isfile("unit_test.test"):
            remove("unit_test.test")
        if path.isfile("unit_test_enc.test"):
            remove("unit_test_enc.test")
        if path.isfile("unit_test_dec.test"):
            remove("unit_test_dec.test")
        open("unit_test.test", "w+").write(UnitTest.test_string * 100)
        SHAXOR.key = UnitTest.test_string
        SHAXOR.inp = "unit_test.test"
        SHAXOR.output = "unit_test_enc.test"
        SHAXOR.enc_file(indicate=False)
        SHAXOR.key = UnitTest.test_string
        SHAXOR.inp = "unit_test_enc.test"
        SHAXOR.output = "unit_test_dec.test"
        SHAXOR.enc_file(indicate=False)
        res = open("unit_test_dec.test", "r").read()
        remove("unit_test.test")
        remove("unit_test_enc.test")
        remove("unit_test_dec.test")
        if res != (UnitTest.test_string * 100):
            print("shaxor.py: error: File encryption unit test error!")
            exit()
        return True

if __name__ == "__main__":
    SHAXOR.show_banner()
    if UnitTest.text_test() and UnitTest.file_test():
        print("        Unit tests was succesfull.\n")
    SHAXOR.set_args()
    SHAXOR.parse_args()
    SHAXOR.decide()
