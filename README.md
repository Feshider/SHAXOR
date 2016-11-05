# SHAXOR
Symetric text and file encryption. This encryption is probably secure if you don't use same key two times.


usage: shaxor.py [-h] -m MODE -i INPUT [-o OUTPUT]

optional arguments:
&nbsp;&nbsp;&nbsp;&nbsp;-h, --help            show this help message and exit
  
&nbsp;&nbsp;&nbsp;&nbsp;-m MODE, --mode MODE  "TEXTENC" - (text) encryption, "FILE" - (path to file) encryption/decryption, "TEXTDEC" - (text) &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;decryption
                        
&nbsp;&nbsp;&nbsp;&nbsp;-i INPUT, --input INPUT
                        Text/File for encryption/decryption.
                        
&nbsp;&nbsp;&nbsp;&nbsp;-o OUTPUT, --output OUTPUT
                        (path to file) if not set, output is printed to
                        terminal.
                        
