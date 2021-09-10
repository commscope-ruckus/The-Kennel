import pexpect
import sys
import re
import time
import cStringIO
from io import StringIO 

#not supported by python3 currently

class APCLI:
    def __init__(self,ap_ip, verbose=False):
        self.ip = ap_ip

    def connect(self, user, passwd, timeout=20, cmd=' '):
        ssh_newkey = 'Are you sure you want to continue connecting'    
        #print "Connecting to %s" % self.ip
        s = pexpect.spawn( 'ssh %s' % self.ip, searchwindowsize = 8 )
        i = s.expect([pexpect.TIMEOUT, ssh_newkey, '.*login:'])
        if i == 1:
            s.sendline( 'yes' )
            s.expect('.*login:')
        s.sendline(user)  # run a command
        s.expect('password :')       
        s.sendline(passwd)  # run a command
        s.expect('rkscli: ')  # match the prompt
        
        s.sendline('') # send newline to see what the shell looks like
        s.expect('rkscli: ')

        s.sendline(cmd)
        s.expect('rkscli: ', timeout = timeout)
        rx = s.before
        if rx:
            rx = rx.replace(cmd, '')
            rx = rx.strip()
            
	
        return cStringIO.StringIO(rx).readlines()
            

#not supported by python3 currently

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print ("Usage: apcli.py apip user pass [cmd]")
        sys.exit(1)

    ap = APCLI(sys.argv[1])
    send_cmd = sys.argv[4]
    res = ap.connect(sys.argv[2], sys.argv[3], 300, send_cmd)
    for aline in res:
        print (aline.rstrip("\n"))
