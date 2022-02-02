"""
OpenNSA backend for Ciena OTN-capable switches.
"""

import random

from twisted.python import log
from twisted.internet import defer

from opennsa import config
from opennsa import constants as cnt
from opennsa.backends.common import genericbackend, ssh

# parameterized commands for layer 2 (NOT IN USE)
COMMAND_CONFIG                  = 'equipmentgrp set shelf 1 group 7' # Equipment group that is configured
COMMAND_SAVE_CONFIG             = 'configuration save'

COMMAND_PORT_DESCRIPTION        = 'port set port %(port)s description %(desc)s' #Set description for a physical port
COMMAND_VSWITCH_CREATE          = 'virtual-switch create vs %(switch)s' #Create virtual switch with a name
COMMAND_SUBPORT_CREATE          = 'sub-port create sub-port %(name)s parent-port %(port)s classifier-precedence %(id)s' #Create virtual interface on a physical port
COMMAND_SUBPORT_ADD_VLAN        = 'sub-port add sub-port %(name)s class-element %(uid)s vtag-stack %(vlan)s' #Create vlan interface on named virtual interface
COMMAND_SUBPORT_CONFIGURE_VLAN  = 'sub-port set sub-port %(name)s ingress-l2-transform push-8100.%(vlan)s.0 egress-l2-transform pop' # Push vlan tag on receiving, pop when sending
COMMAND_ATTACH_SUBPORT          = 'virtual-switch interface attach sub-port %(name)s vs %(switch)s' #Attach virtual interface to virtual switch

# parameterized commands for TL1 (OTN)
MAX_TIMESLOT = 80
COMMAND_LOGIN = 'ACT-USER::%(user)s:%(CTAG)s::%(pass)s'

COMMAND_CRT_PTP_ETH10GFLEX = 'ENT-PTP::PTP-%(port)s:%(CTAG)s:::CONDTYPE=NONE,SERVICETYPE=ETH10GFLEX:IS,AINS' # Configure client port as 10G subrated port
COMMAND_CONFIGURE_NUMSLOTS = 'ED-ODUCTP::ODUCTP-%(port)s-FP1:%(CTAG)s:::NUMTS=%(numslots)s' # Select number of time slots to be assigned, 1 slot = 1 Gbps ethernet
COMMAND_PTP_OOS = 'RMV-PTP::PTP-%(port)s:%(CTAG)s' # Put client card facilities out of service
COMMAND_CRT_ODUCTP_TSASSIGNMENT = 'ENT-ODUCTP::ODUCTP-%(port)s-FP%(FacilityID)s:%(CTAG)s:::GEP=NO,CTPMODE=TRANSPARENT,TSASSIGNMENT=%(TSASSIGN)s,RATE=ODUFLEX:IS' # Create remote-facing ODUCTP facility with given (TSASSIGN) timeslots. Uniqueness of ID in -FP<ID> is from the index of the timeslot used for the connection.
COMMAND_CRT_TCM = 'ENT-TCM::TCMTTP-%(port)sT1:%(CTAG)s:::DMENABLE=NO,TCMMODE=TERMINATED:,AINS-DEA' # Provision TCM part
COMMAND_ODUCTP_OOS = 'RMV-ODUCTP::ODUCTP-%(port)s-FP%(FacilityID)s:%(CTAG)s' # Put ODUCTP facility out of service
COMMAND_ODUCTP_DLT = 'DLT-ODUCTP::ODUCTP-%(port)s-FP%(FacilityID)s:%(CTAG)s' # Delete ODUCTP facility
COMMAND_ODUTTP_OOS = 'RMV-ODUTTP::ODUTTP-%(port)s:%(CTAG)s' # Put ODUTTP facility out of service (NOT USED)
COMMAND_ODUTTP_DLT = 'DLT-ODUTTP::ODUTTP-%(port)s:%(CTAG)s' # Delete ODUTTP facility
COMMAND_TCM_DLT = 'DLT-TCM::TCMTTP-%(port)T1:%(CTAG)s' # Delete TCM facility
COMMAND_PTP_DLT = 'DLT-PTP::PTP-%(port)s:%(CTAG)s' # Delete client port


COMMAND_CRT_CRSCNT_ODUCTP = 'ENT-CRS-ODUCTP::ODUCTP-%(sport)s-FP%(sportFacilityID)s,ODUCTP-%(dport)s-FP%(dportFacilityID)s:%(CTAG)s::%(dir)s:' # Create crossconnect between two ports
COMMAND_DLT_CRSCNT_ODUCTP = 'DLT-CRS-ODUCTP::ODUCTP-%(sport)s-FP%(sportFacilityID)s,ODUCTP-%(dport)s-FP%(dportFacilityID)s:%(CTAG)s::%(dir)s:' # Delete crossconnect between two ports

# String to show in logs
LOG_SYSTEM = 'CIENA'


class CienaLT1SSHChannel(ssh.SSHChannel):

    name = 'session'

    def __init__(self, conn):
        ssh.SSHChannel.__init__(self, conn=conn)

        self.linecache = ''

        self.wait_defer = None
        self.wait_line  = None


    @defer.inlineCallbacks
    def sendCommands(self, commands, username, password, CTAG):
        LT = ";" # Terminates a line in TL1.

        try:
            yield self.conn.sendRequest(self, 'shell', '', wantReply=1)

            result = yield self.executeCommand(COMMAND_LOGIN % {'user':username, 'pass':password, 'CTAG':CTAG})
            if not result:
                raise Exception("Login Failed")

            log.msg('Entered configure mode', system=LOG_SYSTEM)

            for cmd in commands:
                log.msg('CMD> %s' % cmd, system=LOG_SYSTEM)
                result = yield self.executeCommand(cmd)
                if not result:
                    raise Exception("Command failed: %s" % cmd + LT)

            log.msg('Successfully configured', system=LOG_SYSTEM)

        except Exception, e:
            log.msg('Error while sending commands: %s' % str(e), debug=True, system=LOG_SYSTEM)
            raise e

        finally:
            self.sendEOF()
            self.closeIt()


    @defer.inlineCallbacks
    def executeCommand(self, cmd):
        LT = ";" # Terminates a line in TL1.
        d = self.expectedLine(";")
        self.write(cmd + LT)
        lines = yield d
        done = False
        result = False
        terminators = ["COMPLD", "DENY"]
        while not done:
            # wait for a complete line
            # check if the line contains our 'command-termination' (either COMPLD or DENY)
            if len(lines) > 2:
                for line in lines:
                    if any(s in line for s in terminators):
                        done = True
                        if line.find("COMPLD") >= 0:
                            result = True
            if not done:
                d = self.expectedLine(";")
                lines = yield d
        defer.returnValue(result)


    def expectedLine(self, line):
        self.wait_line = line
        self.wait_defer = defer.Deferred()
        return self.wait_defer


    def waitForLine(self, lines):
        for line in lines:
            if self.wait_line and self.wait_defer:
                if self.wait_line == line.strip():
                    d = self.wait_defer
                    self.wait_line  = None
                    self.wait_defer = None
                    d.callback(lines)
                else:
                    pass


    def dataReceived(self, data):
        if len(data) == 0:
            pass
        else:
            self.linecache += data
            if '\n' in data:
                lines = [line.strip() for line in self.linecache.split('\n') if line.strip()]
                self.linecache = ''
                self.waitForLine(lines)

def CienaBackend(network_name, nrm_ports, parent_requester, cfg):

    name = 'Ciena %s' % network_name
    nrm_map  = dict( [ (p.name, p) for p in nrm_ports ] ) # for the generic backend
    port_map = dict( [ (p.name, p) for p in nrm_ports ] ) # for the nrm backend

    host             = cfg[config.CIENA_HOST]
    port             = cfg.get(config.CIENA_PORT, 22)
    host_fingerprint = cfg[config.CIENA_HOST_FINGERPRINT]
    user             = cfg[config.CIENA_USER]
    password         = cfg[config.CIENA_PASSWORD]

    cm = CienaConnectionManager(port_map, host, port, host_fingerprint, user, password,
                                network_name)
    return genericbackend.GenericBackend(network_name, nrm_map, cm, parent_requester, name)

class CienaConnectionManager:

    def __init__(self, port_map, host, port, host_fingerprint, user, password, network_name):
        self.network_name = network_name
        self.port_map = port_map
        self.command_sender = CienaCommandSender(host, port, host_fingerprint, user, password, network_name)
        self.supportedLabelPairs = {
            "otn"  : ['port'],
            "port" : ['otn']
        }


    def getResource(self, port, label):
        assert label is None or label.type_ in (cnt.OTN), 'Label must be None or OTN'
        val = '' if label is None else str(label.labelValue())
        return port + ':' + val


    def getTarget(self, port, label):
        if label is None:
            return CienaTarget(self.port_map[port], port)
        else:
            return CienaTarget(self.port_map[port], port, value=label.labelValue(), lst=label.enumerateValues())


    def createConnectionId(self, source_target, dest_target):
        return 'Ciena-' + str(random.randint(100000,999999))


    def canSwapLabel(self, label_type):
        return True


    def setupLink(self, connection_id, source_target, dest_target, bandwidth):
        def linkUp(_):
            log.msg('Link %s -> %s up' % (source_target, dest_target), system=LOG_SYSTEM)
        d = self.command_sender.setupLink(connection_id,source_target, dest_target,bandwidth)
        d.addCallback(linkUp)
        return d


    def teardownLink(self, connection_id, source_target, dest_target, bandwidth):
        def linkDown(_):
            log.msg('Link %s -> %s down' % (source_target, dest_target), system=LOG_SYSTEM)
        d = self.command_sender.teardownLink(connection_id,source_target, dest_target, bandwidth)
        d.addCallback(linkDown)
        return d

    def canConnect(self, source_port, dest_port, source_label, dest_label):
        src_label_type = 'port' if source_label is None else source_label.type_
        dst_label_type = 'port' if dest_label is None else dest_label.type_

        # By default, accept same types
        if src_label_type == dst_label_type:
            return True
        elif src_label_type in self.supportedLabelPairs and dst_label_type in self.supportedLabelPairs[src_label_type]:
            return True
        else:
            return False

class CienaCommandSender:

    def __init__(self, host, port, ssh_host_fingerprint, user, password,
            network_name):
        self.username = user
        self.password = password

        self.ssh_connection_creator = \
             ssh.SSHConnectionCreator(host, port, [ ssh_host_fingerprint ], username=self.username, password=self.password)
        self.network_name = network_name

    def _getSSHChannel(self):

        def openSSHChannel(ssh_connection):
            channel = CienaLT1SSHChannel(conn = ssh_connection)
            ssh_connection.openChannel(channel)
            return channel.channel_open

        log.msg('Creating new SSH connection', system=LOG_SYSTEM)
        d = self.ssh_connection_creator.getSSHConnection()
        d.addCallback(openSSHChannel)
        return d

    @defer.inlineCallbacks
    def _sendCommands(self, commands, connection_id):

        channel = yield self._getSSHChannel()

        yield channel.sendCommands(commands, self.username, self.password, connection_id[-6:])


    def setupLink(self, connection_id, source_port, dest_port, bandwidth):

        cg = CienaCommandGenerator(connection_id, source_port, dest_port, self.network_name, bandwidth)
        commands = cg.generateActivateCommand() 
        return self._sendCommands(commands, connection_id)


    def teardownLink(self, connection_id, source_port, dest_port, bandwidth):

        cg = CienaCommandGenerator(connection_id, source_port, dest_port, self.network_name, bandwidth)
        commands = cg.generateDeactivateCommand() 
        return self._sendCommands(commands, connection_id)

class CienaTarget(object):

    def __init__(self, port, original_port,value=None, lst=None):
        self.port = port
        self.value = value
        self.lst=lst
        self.original_port = original_port
        # NEVER use ':' in port name!
    def __str__(self):
        if self.port.remote_network is None:
            if self.port.label is not None:
                return '<CienaTarget %s#%s=%s>' % (self.original_port,self.port.label.type_,self.value)
            else:
                return '<CienaTarget %s#>' % (self.original_port)
        else:
            if self.port.label is not None:
                return '<CienaTarget %s#%s=%s -> %s>' % (self.original_port,self.port.label.type_,self.value,self.port.remote_port)
            else:
                return '<CienaTarget %s# -> %s>' % (self.original_port,self.port.remote_port)

class CienaCommandGenerator(object):

    def __init__(self,connection_id,src_port,dest_port,network_name,bandwidth=None):
        self.connection_id = connection_id
        self.src_port = src_port
        self.dest_port = dest_port
        self.bandwidth = bandwidth
        self.network_name = network_name
        self.CTAG = self.connection_id[-6:]
        log.msg('Initialised with params src %s dst %s bandwidth %s connectionid %s' %
                (src_port,dest_port,bandwidth,connection_id), debug=True, system=LOG_SYSTEM)


    # This method takes an iterable containing time slot indexes as a parameter.
    # It returns a TSASSIGNMENT bitmask, which is used in remote connections only.
    def generateTimeSlotAssignment(self, slots):
        bitmask = 0

        for slot in slots:
            bitmask |= 1 << (MAX_TIMESLOT - slot)

        formatted = format(bitmask, "020X")

        return "-".join([formatted[i:i+4] for i in range(0, len(formatted), 4)])


    def generateActivateCommand(self):
        commands = []

        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("%s %s " % (self.src_port,self.dest_port))
        log.msg("Activating commands between %s and %s " % (source_port,dest_port), system=LOG_SYSTEM)


        if source_port.remote_network is None and dest_port.remote_network is None:
            commands = self._generateLocalConnectionActivate() # Here the ports are client ports to crossconnect
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            commands = self._generateLocalConnectionActivate() # Here we have two remote ports.
        else:
            commands = self._generateRemoteConnectionActivate() # Here we have one client port and one remote port.
        return commands


    def generateDeactivateCommand(self):
        commands = []

        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("Deactivating between %s and %s " % (source_port,dest_port), system=LOG_SYSTEM)


        if source_port.remote_network is None and dest_port.remote_network is None:
            commands = self._generateLocalConnectionDeActivate() # Here the ports are crossconnected client ports
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            commands = self._generateLocalConnectionDeActivate() # Here we have two remote ports.
        else:
            commands = self._generateRemoteConnectionDeActivate() # Here we have one client port and one remote port.

        return commands


    def _generateLocalConnectionActivate(self):
        commands = []

        src_timeslots = self.src_port.lst
        src_numslots = len(src_timeslots)
        dst_timeslots = self.dest_port.lst
        dst_numslots = len(dst_timeslots)
        src_facilityid = src_timeslots[0]
        dst_facilityid = dst_timeslots[0]

        source_port = self.src_port.port
        dest_port = self.dest_port.port

        if source_port.label is None and dest_port.label is None:
            # The facility IDs are hardcoded to 1, as client ports cannot have more than 1 ODUCTP facility and here we only deal with client ports.
            commands.append(COMMAND_CRT_PTP_ETH10GFLEX % { 'port':source_port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_CONFIGURE_NUMSLOTS % { 'port':source_port.interface, 'CTAG':self.CTAG, 'numslots':src_numslots})
            commands.append(COMMAND_CRT_PTP_ETH10GFLEX % { 'port':dest_port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_CONFIGURE_NUMSLOTS % { 'port':dest_port.interface, 'CTAG':self.CTAG, 'numslots':dst_numslots})
            commands.append(COMMAND_CRT_CRSCNT_ODUCTP % {'sport':source_port.interface, 'sportFacilityID':1, 'dport':dest_port.interface, 'dportFacilityID':1, 'CTAG':self.CTAG, 'dir': "2WAY"})

        elif source_port.label is not None and dest_port.label is not None:
            # Here we create a transiting connection consisting of two remote ports
            commands.append(COMMAND_CRT_ODUCTP_TSASSIGNMENT % { 'port':source_port.interface, 'FacilityID':src_facilityid, 'CTAG':self.CTAG, 'TSASSIGN':self.generateTimeSlotAssignment(src_timeslots)})
            commands.append(COMMAND_CRT_ODUCTP_TSASSIGNMENT % { 'port':dest_port.interface, 'FacilityID':dst_facilityid, 'CTAG':self.CTAG, 'TSASSIGN':self.generateTimeSlotAssignment(dst_timeslots)})
            commands.append(COMMAND_CRT_CRSCNT_ODUCTP % { 'sport':source_port.interface, 'sportFacilityID': src_facilityid, 'dport':dest_port.interface, 'dportFacilityID':dst_facilityid, 'CTAG':self.CTAG, 'dir':"2WAY"})

        log.msg("Activate: %s %s" % (self.src_port.original_port,self.dest_port.original_port), system=LOG_SYSTEM)

        return commands


    def _generateLocalConnectionDeActivate(self):
        commands = []

        src_timeslots = self.src_port.lst
        src_numslots = len(src_timeslots)
        dst_timeslots = self.dest_port.lst
        dst_numslots = len(dst_timeslots)
        src_facilityid = src_timeslots[0]
        dst_facilityid = dst_timeslots[0]

        source_port = self.src_port.port
        dest_port = self.dest_port.port

        if source_port.label is None and dest_port.label is None:
            # The facility IDs are hardcoded to 1, as client ports cannot have more than 1 ODUCTP facility and here we only deal with client ports.
            commands.append(COMMAND_DLT_CRSCNT_ODUCTP % {'sport':source_port.interface, 'sportFacilityID':1, 'dport':dest_port.interface, 'dportFacilityID':1, 'CTAG':self.CTAG, 'dir':"2WAY"})
            commands.append(COMMAND_PTP_OOS % { 'port':source_port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':source_port.interface, 'FacilityID':1, 'CTAG':self.CTAG})
            commands.append(COMMAND_PTP_DLT % { 'port':source_port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_PTP_OOS % { 'port':dest_port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':dest_port.interface, 'FacilityID':1, 'CTAG':self.CTAG})
            commands.append(COMMAND_PTP_DLT % { 'port':dest_port.interface, 'CTAG':self.CTAG})

        elif source_port.label is not None and dest_port.label is not None:
            # Here we delete a transiting connection consisting of two remote ports
            commands.append(COMMAND_DLT_CRSCNT_ODUCTP % {'sport':source_port.interface, 'sportFacilityID':src_facilityid, 'dport':dest_port.interface, 'dportFacilityID':dst_facilityid, 'CTAG':self.CTAG, 'dir':"2WAY"})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':source_port.interface, 'FacilityID':src_facilityid, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_DLT % { 'port':source_port.interface, 'FacilityID':src_facilityid, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':dest_port.interface, 'FacilityID':dst_facilityid, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_DLT % { 'port':dest_port.interface, 'FacilityID':dst_facilityid, 'CTAG':self.CTAG})


        log.msg("Deactivate: %s %s" % (self.src_port.original_port,self.dest_port.original_port), system=LOG_SYSTEM)

        return commands

    def _generateRemoteConnectionActivate(self):
        commands = []

        local_port = self.src_port if self.src_port.port.remote_network is None else self.dest_port
        remote_port = self.src_port if self.src_port.port.remote_network is not None else self.dest_port
        log.msg("Local port: %s" % local_port.original_port)
        log.msg("Remote port: %s" % remote_port.original_port)

        assert local_port.port.label is None # This version only supports whole ports on the client ports.

        timeslots = remote_port.lst
        numslots = len(timeslots)
        facilityid = timeslots[0]

        commands.append(COMMAND_CRT_PTP_ETH10GFLEX % { 'port':local_port.port.interface, 'CTAG':self.CTAG})
        commands.append(COMMAND_CONFIGURE_NUMSLOTS % { 'port':local_port.port.interface, 'CTAG':self.CTAG, 'numslots':numslots})

        if remote_port.port.label is not None and remote_port.port.label.type_ == "otn":
            commands.append(COMMAND_CRT_ODUCTP_TSASSIGNMENT % { 'port':remote_port.port.interface, 'FacilityID':facilityid, 'CTAG':self.CTAG, 'TSASSIGN':self.generateTimeSlotAssignment(timeslots)})
            commands.append(COMMAND_CRT_CRSCNT_ODUCTP % { 'sport':local_port.port.interface, 'sportFacilityID': 1, 'dport':remote_port.port.interface, 'dportFacilityID':facilityid, 'CTAG':self.CTAG, 'dir':"2WAY"})
        return commands

    def _generateRemoteConnectionDeActivate(self):
        commands = []

        local_port = self.src_port if self.src_port.port.remote_network is None else self.dest_port
        remote_port = self.src_port if self.src_port.port.remote_network is not None else self.dest_port
        log.msg("Local port: %s" % local_port.original_port)
        log.msg("Remote port: %s" % remote_port.original_port)

        assert local_port.port.label is None # This version only supports whole ports on the client ports.

        timeslots = remote_port.lst
        numslots = len(timeslots)
        facilityid = timeslots[0]

        if remote_port.port.label is not None and remote_port.port.label.type_ == "otn":
            commands.append(COMMAND_DLT_CRSCNT_ODUCTP % {'sport':local_port.port.interface, 'sportFacilityID':1, 'dport':remote_port.port.interface, 'dportFacilityID':facilityid, 'CTAG':self.CTAG, 'dir':"2WAY"})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':remote_port.port.interface, 'FacilityID':facilityid, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_DLT % { 'port':remote_port.port.interface, 'FacilityID':facilityid, 'CTAG':self.CTAG})
            commands.append(COMMAND_PTP_OOS % { 'port':local_port.port.interface, 'CTAG':self.CTAG})
            commands.append(COMMAND_ODUCTP_OOS % { 'port':local_port.port.interface, 'FacilityID':1, 'CTAG':self.CTAG})
            commands.append(COMMAND_PTP_DLT % { 'port':local_port.port.interface, 'CTAG':self.CTAG})

        return commands