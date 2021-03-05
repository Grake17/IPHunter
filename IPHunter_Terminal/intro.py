





import os
import time, sys


os.system("cls")

"""COLORS = {\
"black":"\u001b[30;1m",
"red": "\u001b[31;1m",
"green":"\u001b[32;1m",
"yellow":"\u001b[33m",
"blue":"\u001b[34;1m",
"magenta":"\u001b[35m",
"cyan": "\u001b[36m",
"white":"\u001b[37m",
"yellow-background":"\u001b[43m",
"black-background":"\u001b[40m",
"cyan-background":"\u001b[46;1m",
}
#You can add more colors and backgrounds to the dictionary if you like.


def colorText(text):
    for color in COLORS:
        text = text.replace("[" + color + "]", COLORS[color])
    return text


import time, sys
"""

def loading():
    print("Loading...")
    for i in range(0, 90):
        os.system("cls")
        path = "start\zero\ozero" + str(i) + ".txt"
        a = open(path, "r")
        ascii = "".join(a.readlines())
        print(ascii)
        time.sleep(0.1)


loading()


