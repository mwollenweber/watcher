#!/usr/bin/python
'''

Copyright Matthew Wollenweber 2012
mjw@cyberwart.com
All Rights Reserved.

'''
__description__ = ''
__author__ = 'Matthew Wollenweber'
__email__ = 'mjw@cyberwart.com'
__version__ = '0.1'
__date__ = '2013/05/06'


try:
    import os
    import sys
    import argparse
    import ConfigParser
    import logging
    import signal
    import subprocess
    import time
    import traceback
    
except ImportError, e:
        from notify import *
        self._log.error('Failed to import the proper libraries')
        notify("Failed to import all libs",str(e),"INFO",True)


DEBUG = True
        

class alerter:
    def __init__(self, logger = None):
        print "alerter"
        self.logger = logger
        self.has_alert = False
    
    def send_alert_email(self):
        print "sending alert email"
        
    def log_alert(self):
        print "logging alert"
        
    def has_alert_handler(self):
        if self.alert_set == True:
            return True
        else:
            return False
        
    def alert(self, e = None, note = None):
        self.logger.info("alert triggered")
        


class tcpdumpd:
    def __init__(self, logger = None):
        if logger == None:
            logger = logging.getLogger('')
            logger.setLevel(logging.DEBUG)
            logger.addHandler(logging.StreamHandler())
            self.logger = logger
        else:
            self.logger = logger
            

        #FIXME CONFIG
        self.pid = -1
        self.status = 0
        self.ROTATE_TIME = 0
        self.ROTATE_PERIOD = 90
        self.PID_FILE = '/tmp/tcpdump.pid'
        #self.TCPDUMP_ARGS = ' -i en0 -qStnnvs 1500 -w out.dump ip '
        #self.TCPDUMP_ARGS = '-w out.dump ip'
        self.TCPDUMP_ARGS = ['-i en0', '-qStnnvs 1500', '-w out.dump', 'ip']
        self.TCPDUMP_DATADIR = '/data/tcpdump/vip'
        self.TCPDUMP = '/opt/local/sbin/tcpdump'
        
        self.cmd = ['tcpdump', '-i', 'en0', '-qStnnv', '-w', 'out.dump', 'ip']
        self.tcpd_proc = None
    
    def get_pid(self):
        return int(self.pid)
    
    def get_status(self):
        return int(self.status)
    
    def rotate_pcaps(self):
        self.logger.debug("Rotating pcap files")
        
        
    def get_config(self, path = None):
        config = ConfigParser.ConfigParser()
        error_count = 0
        if path == None:
            try:
                os.stat("./tcpdumpd.cfg")
                if error_count == 0:
                    config.readfp("./tcpdump.cfg")
                else:  
                    config.readfp("~/.tcpdump-cfg")
                    
            except:
                self.logger.debug("fuxor")
                if error_count == 0:
                    error_count += 1
                    pass
                else:
                    logging.ERROR("CANNOT FIND CONFIG....Exiting")
                    traceback.print_exc(file=sys.stderr)
                    sys.exit(-1)
            
        return True
    
    def verify_or_mkdir(self, path):
        try:
            os.makedirs(path)
        except OSError as exc: # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise
            
    def spawn_tcpdump(self):
        
        #rotate the previous output file
        
        self.ROTATE_TIME = time.time() + self.ROTATE_PERIOD
        
        logging.debug("Attempting to run tcpdump. CMD = %s" % (self.cmd))
        self.tcpd_proc =  subprocess.Popen(self.cmd, stdout=subprocess.PIPE)
  
        self.pid = int(self.tcpd_proc.pid)
        logging.debug("tcpdump pid=%s" %self.pid)
        
    
        
        return
    
    def kill_tcpdump(self):
        self.logger.debug("killing tcpdump via subprocess")
        self.tcpd_proc.kill()
        os.waitpid(self.get_pid(), 0)
        
        self.tcpd_proc = None
        self.pid = -1
        self.status = -100
        self.logger.debug("done killing tcpdump")
        
    
    def check_tcpdump(self):
        try:
            #check if process is running
            os.kill(self.get_pid(), 0)
            
            retcode = self.tcpd_proc.poll()
            if retcode is not None:
                self.logger.error("tcpdump PID=%s is not running" % self.get_pid())
                self.status = -1
                self.pid = -1
                return False

            self.logger.debug("PID=%s seems okay" % self.get_pid())
            return True
            
        except OSError:
            self.status = -1
            self.pid = -1
            self.logger.error("tcpdump PID=%s is not running" % self.get_pid())
            return False
        
        except:
            self.logger.debug("unknown random error in check_tcpdump")
            self.status = -2
            return False
            

def main():
    parser = argparse.ArgumentParser(prog='template', usage='%(prog)s [options]')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--version', action='version', version='%(prog)s -1.0')
    parser.add_argument('--debug', '-D', type=bool, dest='DEBUG', default=False)


    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    tcpd = tcpdumpd(logger = logger)
    my_alerter = alerter(logger = logger)


    #check if PID file exists
    try:
        f = open(tcpd.PID_FILE, "r")
        pid = f.read()
        tcpd.logger.debug("PID FILE Exists")
            
        #check if process is running
        os.kill(pid, 0)
        tcpd.logger.debug("PID seems okay")
             
    except IOError:
        tcpd.logger.debug("No existing PID file")
        tcpd.spawn_tcpdump()
        
        
    except OSError:
        tcpd.logger.debug("PID file exists, but the process does not")
        os.remove(PID_FILE)
        tcpd.spawn_tcpdump()
    
    
    while 1 == 1:
        try:
            if tcpd.check_tcpdump() == False:
                tcpd.logger.error("tcpdump died. Respawning")
                tcpd.spawn_tcpdump()
                tcpd.logger.debug("time is %s. Running until %s" % (time.time(), tcpd.ROTATE_TIME))
                my_alerter.alert()
                
            #fixme this should all be inside the class
            if time.time() >= tcpd.ROTATE_TIME:
                tcpd.logger.debug("Rotating tcpdump. Killing PID %s and respawning" % tcpd.pid)
                
                #fixme this chain of events is basically just a restart
                tcpd.kill_tcpdump()
                tcpd.spawn_tcpdump()
                tcpd.clean_outfiles()
                
            tcpd.logger.debug("tcpdump looks good...sleeping")
            time.sleep(5)           
        except (KeyboardInterrupt, SystemExit):
            tcpd.logger.error("Caught interupt, exiting")
            tcpd.kill_tcpdump()
            sys.exit(-1)
            #raise
        
        except:
            tcpd.logger.error("Exiting")
            sys.exit(-1)
                

if __name__ == "__main__":
    main()
    
    