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
    import magic
    import re
    import signal
    import socket
    import subprocess
    import time
    import threading
    import traceback
    import zipfile
    
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
    def __init__(self, logger = None, source = None):
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
        self.exe = "tcpdump"
        self.arg_str = '-i en0 -qStnnvs 1500 -w %s ip'
        self.PID_FILE = '/tmp/tcpdump.pid'
        self.TCPDUMP_ARGS_STR = ' -i en0 -qStnnvs 1500 -w %s ip '
        self.TCPDUMP_ARGS = ['-i en0', '-qStnnvs 1500', '-w out.dump', 'ip']
        self.DATADIR = '/data/tcpdump/vip'
        self.TCPDUMP = '/opt/local/sbin/tcpdump'
        self.filterexp = None
        if source == None:
            self.source = socket.gethostname()
        
        self.cmd = ['tcpdump', '-i', 'en0', '-qStnnv', '-w', 'out.dump', 'ip']
        self.tcpd_proc = None
        self.build_cmd()

    def build_outfilename(self, prefix = '', base = '', suffix = '', ext = ''):
        #filename = self.source + "-" + time.strftime('%Y%m%d%H%M%S') + ".pcap"
        ext = ".pcap"
        filename = prefix + self.source + "-" + base + "-" + time.strftime('%Y%m%d%H%M%S') +suffix + ext
        return filename
    
        
    #FIXME. Basically need to decorate the arg_str to replace any "%s". Need to generalize
    def build_cmd(self, exe = None, arg_str = None):
        if exe == None:
            if self.exe != None:
                exe = self.exe
            else:
                self.logger.error("No executable defined. Exiting")
                sys.exit(-1)
        
        if arg_str == None:
            if self.arg_str != None:
                arg_str = self.arg_str
            else:
                self.logger.debug("no args given")
                arg_str = ""
                
        #fills in variables for the arg str and builds the command
        filename = self.build_outfilename()
        arg_str = arg_str % (filename)
        cmd = exe + "  " + arg_str
        self.cmd = cmd.split()
        return self.cmd
    
    
    def filter_files(self, filelist):
        exp = self.filterexp
        if exp == None or exp == '':
            return filelist
        
        filtered_list = []
        for x in filelist:
            if re.search(exp, x):
                filtered_list.append(x)
                
        return filtered_list
    
    def get_pid(self):
        return int(self.pid)
    
    def get_status(self):
        return int(self.status)
    
    def get_datadir(self):
        return str(self.DATADIR)
    
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
        self.build_cmd()
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
        
    def clean_outfiles():
        print "clean_outfiles: FIXME"
        
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

    def zipfiles(self, filename):
      
        
        
    def get_filenames(self, path=None, regex = None):
        if path == None:
            path = self.get_datadir()
        
        filelist = []
        if path == None:
            return filelist
        
        try:
            for root, dirs, files in os.walk(path):
                for name in files:       
                    filename = os.path.join(root, name)
                    filelist.append(filename)
        except:
            traceback.print_exc(file=sys.stderr)
            sys.exit(-1)
            
        return filelist
    
    def kill(self):
        self.logger.debug("Killing processes")
        self.kill_tcpdump()
        

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
                #tcpd.clean_outfiles()
                
            tcpd.logger.debug("tcpdump looks good...sleeping")
            time.sleep(5)           
        except (KeyboardInterrupt, SystemExit):
            tcpd.logger.error("Caught interupt, exiting")
            tcpd.kill()
            sys.exit(-1)
            #raise
        
        except:
            tcpd.logger.error("Unknown ERROR in main. Exiting")
            traceback.print_exc(file=sys.stderr)
            tcpd.kill()
            sys.exit(-1)
                

if __name__ == "__main__":
    main()
    
    