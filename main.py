# pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org opencv-python cryptography==2.8 cose cbor2 base45 pyzbar wxPython

# import the opencv library
import cv2
import json
import sys
import zlib
import base45
import cbor2
from pyzbar import pyzbar
from base64 import b64decode, b64encode

from cose.keys.curves import P256
from cose.algorithms import Es256, Ps256
from cose.headers import KID
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage
from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

import wx

resX = 1200
resY = 800

debug = False

kids = {}
valuesets = {}


class Frame(wx.Frame):
    def __init__(self, title, text):
        wx.Frame.__init__(self, None, title=title, size=(300, 200))

        self.panel = wx.Panel(self)
        box = wx.BoxSizer(wx.VERTICAL)
        m_text = wx.StaticText(self.panel, -1, text)
        m_text.SetSize(m_text.GetBestSize())

        box.Add(m_text, 0, wx.ALL, 10)
        self.panel.SetSizer(box)
        self.panel.Layout()

        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.onClose, self.timer)
        self.timer.Start(3000)

    def onClose(self, event):
        self.Close()


def checkGreenpass(greenpasscode):
    payload = greenpasscode[4:]
    try:
        decoded = base45.b45decode(payload)
    except:
        return
    decompressed = zlib.decompress(decoded)
    cose = CoseMessage.decode(decompressed)
    valid = signature_valid(cose)
    greenpassdata = cbor2.loads(cose.payload)
    app = wx.App(redirect=True)
    cognome = greenpassdata[-260][1]['nam']['fnt']
    nome = greenpassdata[-260][1]['nam']['gnt']
    datanascita = greenpassdata[-260][1]['dob']
    if valid:
        top = Frame('Greenpass valido', text=cognome + ' ' + nome + ' ' + datanascita)
    else:
        top = Frame('Greenpass NON valido!!', cognome + ' ' + nome + ' ' + datanascita)
    top.Show()
    app.MainLoop()


def add_kid(kid_b64, key_b64):
    kid = b64decode(kid_b64)
    asn1data = b64decode(key_b64)

    pub = serialization.load_der_public_key(asn1data)
    if isinstance(pub, RSAPublicKey):
        kids[kid_b64] = CoseKey.from_dict(
            {
                KpKty: KtyRSA,
                KpAlg: Ps256,  # RSSASSA-PSS-with-SHA-256-and-MFG1
                RSAKpE: int_to_bytes(pub.public_numbers().e),
                RSAKpN: int_to_bytes(pub.public_numbers().n)
            })
    elif isinstance(pub, EllipticCurvePublicKey):
        kids[kid_b64] = CoseKey.from_dict(
            {
                KpKty: KtyEC2,
                EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
                KpAlg: Es256,  # ecdsa-with-SHA256
                EC2KpX: pub.public_numbers().x.to_bytes(32, byteorder="big"),
                EC2KpY: pub.public_numbers().y.to_bytes(32, byteorder="big")
            })
    else:
        print(f"Skipping unexpected/unknown key type (keyid={kid_b64}, {pub.__class__.__name__}).", file=sys.stderr)


def load_pub_keys():
    # keys = urlopen('https://verifier-api.coronacheck.nl/v4/verifier/public_keys')
    keys = open('public_keys.json')
    pkg = json.load(keys)
    payload = b64decode(pkg['payload'])
    trustlist = json.loads(payload)
    eulist = trustlist['eu_keys']
    for kid_b64 in eulist:
        add_kid(kid_b64, eulist[kid_b64][0]['subjectPk'])


def signature_valid(cose):
    given_kid = None
    if KID in cose.phdr.keys():
        given_kid = cose.phdr[KID]
    else:
        given_kid = cose.uhdr[KID]

    given_kid_b64 = b64encode(given_kid).decode('ASCII')

    if given_kid_b64 in kids:
        key = kids[given_kid_b64]

        cose.key = key
        if not cose.verify_signature():
            return False
        else:
            return True
    else:
        return False


# --- MAIN ---
# define a video capture object
vid = cv2.VideoCapture(0)
detector = cv2.QRCodeDetector()

load_pub_keys()

while True:
    ret, frame = vid.read()

    frameResized = cv2.resize(frame, (resX, resY), interpolation=cv2.INTER_AREA)
    cv2.imshow('Verifica Greenpass', frameResized)
    cv2.resizeWindow('Verifica Greenpass', resX, resY)

    # Decode the QR Code
    mask = cv2.inRange(frame, (0, 0, 0), (200, 200, 200))
    thresholded = cv2.cvtColor(mask, cv2.COLOR_GRAY2BGR)
    inverted = 255 - thresholded  # black-in-white
    barcodes = pyzbar.decode(inverted)
    if debug:
        cv2.imshow('Verifica Greenpass', inverted)
        print(barcodes)
    if barcodes:
        greenpassCode = str(barcodes[0].data)[2:-1]
        if debug:
            print(greenpassCode)
        checkGreenpass(greenpassCode)
    # Press q to quit
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# After the loop release the cap object
vid.release()
# Destroy all the windows
cv2.destroyAllWindows()
