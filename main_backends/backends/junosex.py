"""
OpenNSA backend for Juniper EX switches supporting ccc encapsulation.

Even though mpls is used here, mpls to other devices is not supported. MPLS is
merely to facilitate private switching between two units. So only vlan-vlan
connections are supported.

Authors:
Original GTS backend: Tamas Varga <vargat@niif.hu>
Modified for EX4550 Michal Hazlinksy <hazlinsky@cesnet.cz>
"""

import random

from twisted.python import log
from twisted.internet import defer

from opennsa import config
from opennsa.backends.common import genericbackend, ssh



# parameterized commands
COMMAND_CONFIGURE           = 'edit private'
COMMAND_COMMIT              = 'commit'
COMMAND_COMMIT_COMPLETE     = b'commit complete'

COMMAND_SET_INTERFACES      = 'set interfaces %(port)s encapsulation ethernet-ccc' # port, source vlan, source vlan
COMMAND_SET_INTERFACES_CCC  = 'set interfaces %(port)s unit 0 family ccc'
COMMAND_SET_INTERFACES_MTU  = 'set interfaces %(port)s mtu 9000'

COMMAND_SET_INTERFACE_VLN_T = 'set interfaces %(port)s vlan-tagging'
COMMAND_SET_INTERFACE_ENC_V = 'set interfaces %(port)s encapsulation vlan-ccc'
COMMAND_SET_VLAN_ENCAP      = 'set interfaces %(port)s unit %(vlan)s encapsulation vlan-ccc'
COMMAND_SET_VLAN_ID         = 'set interfaces %(port)s unit %(vlan)s vlan-id %(vlan)s'
COMMAND_SET_SWAP_PUSH_POP   = 'set interfaces %(port)s unit %(vlan)s swap-by-poppush'

COMMAND_DELETE_INTERFACES   = 'delete interfaces %(port)s' # port / vlan
COMMAND_DELETE_INTERFACES_VL= 'delete interfaces %(port)s.%(vlan)s'
COMMAND_DELETE_CONNECTIONS  = 'delete protocols connections interface-switch %(switch)s' # switch

COMMAND_DELETE_MPLS_LSP     = 'delete protocols mpls label-switched-path %(unique-id)s'
COMMAND_DELETE_REMOTE_INT_SW= 'delete protocols connections remote-interface-switch %(connectionid)s'

COMMAND_LOCAL_CONNECTIONS   = 'set protocols connections interface-switch %(switch)s interface %(interface)s.%(subinterface)s'

COMMAND_REMOTE_LSP_OUT_TO   = 'set protocols mpls label-switched-path %(unique-id)s to %(remote_ip)s'
COMMAND_REMOTE_LSP_OUT_NOCSPF = 'set protocols mpls label-switched-path %(unique-id)s no-cspf'

COMMAND_REMOTE_CONNECTIONS_INT = 'set protocols connections remote-interface-switch %(connectionid)s interface %(port)s'
COMMAND_REMOTE_CONNECTIONS_TRANSMIT_LSP = 'set protocols connections remote-interface-switch %(connectionid)s transmit-lsp %(unique-id)s'
COMMAND_REMOTE_CONNECTIONS_RECEIVE_LSP  = 'set protocols connections remote-interface-switch %(connectionid)s receive-lsp %(unique-id)s'

LOG_SYSTEM = 'EX4550'



class SSHChannel(ssh.SSHChannel):

    name = 'session'

    def __init__(self, conn):
        ssh.SSHChannel.__init__(self, conn=conn)

        self.linecache = b''

        self.wait_defer = None
        self.wait_line  = None


    @defer.inlineCallbacks
    def sendCommands(self, commands):
        LT = '\r' # line termination

        try:
            yield self.conn.sendRequest(self, b'shell', b'', wantReply=1)

            d = self.expectedLine('[edit]')
            self.write(COMMAND_CONFIGURE + LT)
            yield d

            log.msg('Entered configure mode', debug=True, system=LOG_SYSTEM)

            for cmd in commands:
                log.msg('CMD> %s' % cmd, system=LOG_SYSTEM)
                d = self.expectedLine('[edit]')
                self.write(cmd.encode() + LT)
                yield d

            d = self.expectedLine('[edit]')
            self.write(COMMAND_COMMIT + LT)
            lines = yield d

            if self.commitFailed(lines):
                raise Exception("Commit failed: %s" % '\n'.join(lines))

            log.msg('Commands successfully committed', debug=True, system=LOG_SYSTEM)

        except Exception as e:
            log.msg('Error sending commands: %s' % str(e))
            raise e

        finally:
            self.sendEOF()
            self.closeIt()
            self.closeConnection()

    def commitFailed(self, lines):
        for line in lines:
            if line == COMMAND_COMMIT_COMPLETE:
                return False
        return True


    def expectedLine(self, line):
        self.wait_line = line.encode()
        self.wait_defer = defer.Deferred()
        return self.wait_defer


    def matchLine(self, lines):
        if self.wait_line and self.wait_defer:
            for line in lines:
                if self.wait_line in line:
                    d = self.wait_defer
                    self.wait_line  = None
                    self.wait_defer = None
                    d.callback(lines)
                    return True
        return False


    def dataReceived(self, data):
        if len(data) == 0:
            pass
        else:
            self.linecache += data
            if b'\n' in data:
                lines= []
                for line in self.linecache.split(b'\n'):
                    lines.append(line.strip())
                if(self.matchLine(lines)):
                    self.linecache = b''



## TODO:   Continue HERE 
class JunosEx4550CommandSender:

    def __init__(self, host, port, ssh_host_fingerprint, user, ssh_public_key_path, ssh_private_key_path,
            network_name):
        self.ssh_connection_creator = \
             ssh.SSHConnectionCreator(host, port, [ ssh_host_fingerprint.encode() ], user, ssh_public_key_path, ssh_private_key_path)

        self.network_name = network_name
        self.sem = defer.DeferredSemaphore(1)

    def _getSSHChannel(self):

        def openSSHChannel(ssh_connection):
            channel = SSHChannel(conn = ssh_connection)
            ssh_connection.openChannel(channel)
            return channel.channel_open

        log.msg('Creating new SSH connection', system=LOG_SYSTEM)
        d = self.ssh_connection_creator.getSSHConnection()
        d.addCallback(openSSHChannel)
        return d


    @defer.inlineCallbacks
    def _sendCommands(self, commands):

        channel = yield self._getSSHChannel()
        yield channel.sendCommands(commands)

    def setupLink(self, connection_id, source_port, dest_port, bandwidth):

        cg = JunosEx4550CommandGenerator(connection_id,source_port,dest_port,self.network_name,bandwidth)
        commands = cg.generateActivateCommand() 
        return self.sem.run(self._sendCommands, commands)


    def teardownLink(self, connection_id, source_port, dest_port, bandwidth):

        cg = JunosEx4550CommandGenerator(connection_id,source_port,dest_port,self.network_name,bandwidth)
        commands = cg.generateDeactivateCommand() 
        return self.sem.run(self._sendCommands, commands)


class JunosEx4550Target(object):

    def __init__(self, port, original_port,value=None):
        self.port = port
        self.value = value
        self.original_port = original_port
        # NEVER USE : in port name! 
    def __str__(self):
        if self.port.remote_network is None:
            return '<JuniperEX4550Target %s#%s=%s>' % (self.original_port,self.port.label.type_,self.value)
        else:
            return '<JuniperEX4550Target %s#%s=%s -> %s>' % (self.original_port,self.port.label.type_,self.value,self.port.remote_port,)



class JunosEx4550ConnectionManager:

    def __init__(self, port_map, host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
            network_name):
        self.network_name = network_name
        self.port_map = port_map
        self.command_sender = JunosEx4550CommandSender(host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
                network_name)


    def getResource(self, port, label):
        return self.port_map[port] + ':' + '' if label is None else str(label.labelValue())


    def getTarget(self, port, label):
        return JunosEx4550Target(self.port_map[port], port,label.labelValue())


    def createConnectionId(self, source_target, dest_target):
        return 'JuniperEx4550-' + str(random.randint(100000,999999))


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



def JunosEXBackend(network_name, nrm_ports , parent_requester, cfg):

    name = 'JunosEX %s' % network_name
    nrm_map  = dict( [ (p.name, p) for p in nrm_ports ] ) # for the generic backend
    port_map = dict( [ (p.name, p) for p in nrm_ports ] ) # for the nrm backend

    host             = cfg[config.JUNIPER_HOST]
    port             = cfg.get(config.JUNIPER_PORT, 22)
    host_fingerprint = cfg[config.JUNIPER_HOST_FINGERPRINT]
    user             = cfg[config.JUNIPER_USER]
    ssh_public_key   = cfg[config.JUNIPER_SSH_PUBLIC_KEY]
    ssh_private_key  = cfg[config.JUNIPER_SSH_PRIVATE_KEY]

    cm = JunosEx4550ConnectionManager(port_map, host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
            network_name)
    return genericbackend.GenericBackend(network_name, nrm_map, cm, parent_requester, name)


class JunosEx4550CommandGenerator(object):

    def __init__(self,connection_id,src_port,dest_port,network_name,bandwidth=None):
        self.connection_id = connection_id
        self.src_port = src_port
        self.dest_port = dest_port
        self.bandwidth = bandwidth
        self.network_name = network_name
        log.msg('Initialised with params src %s dst %s bandwidth %s connectionid %s' %
                (src_port,dest_port,bandwidth,connection_id), debug=True, system=LOG_SYSTEM)


    def generateActivateCommand(self):
        commands = []

        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("%s %s " % (source_port,dest_port))
        log.msg("Activate commands between %s:%s:%s and %s:%s:%s " % 
                (source_port.remote_network, source_port.interface, source_port.label.type_,
                    dest_port.remote_network, dest_port.interface, dest_port.label.type_), debug=True,
                system=LOG_SYSTEM)

        # Local connection
        if source_port.remote_network is None and dest_port.remote_network is None:
            commands = self._generateLocalConnectionActivate()
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            commands = self._generateLocalConnectionActivate()
            log.msg('Transit connection-HERE SHOULD BE COMMANDS FOR TRANSIT', system=LOG_SYSTEM)
        else:
            #commands = self._generateRemoteConnectionActivate()  All cases are the same tODO: remove IFs competely here 
            commands = self._generateLocalConnectionActivate()
        return commands


    def generateDeactivateCommand(self):
        commands = {}

        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("Deactivate commands between %s:%s#%s=%s and %s:%s#%s=%s " % 
                (source_port.remote_network, source_port.interface, source_port.label.type_,self.src_port.value,
                    dest_port.remote_network, dest_port.interface, dest_port.label.type_,self.dest_port.value), debug=True,
                system=LOG_SYSTEM)

        # Local connection 
        if source_port.remote_network is None and dest_port.remote_network is None:
            commands = self._generateLocalConnectionDeActivate()
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            #commands = ["Transit connection"]
            commands = self._generateLocalConnectionDeActivate()
        else: 
            #commands = self._generateRemoteConnectionDeactivate()   DTTO as activate
            commands = self._generateLocalConnectionDeActivate()

        return commands


    def _createSwitchName(self,connection_id):

        switch_name = 'OpenNSA-local-%s' % (connection_id)

        return switch_name


    def _generateLocalConnectionActivate(self):
        commands = []
        switch_name = self._createSwitchName( self.connection_id )

        """ For configuration reason, we're going to generate port things first, then the interface-switch commands"""
        for gts_port in self.src_port,self.dest_port:
            #if gts_port.port.label is not None and gts_port.port.label.type_ == "port":
            #    commands.append( COMMAND_SET_INTERFACES % { 'port':gts_port.port.interface} )
            #    commands.append( COMMAND_SET_INTERFACES_MTU % { 'port':gts_port.port.interface} )
            #    commands.append( COMMAND_SET_INTERFACES_CCC % { 'port':gts_port.port.interface} )
            # tODO remove this as ports are not supported 
            if gts_port.port.label is not None and gts_port.port.label.type_ == "vlan":
                commands.append( COMMAND_SET_INTERFACE_VLN_T % {'port':gts_port.port.interface, 'vlan':gts_port.value} )
                commands.append( COMMAND_SET_INTERFACES_MTU % { 'port':gts_port.port.interface} )
                commands.append( COMMAND_SET_INTERFACE_ENC_V % {'port':gts_port.port.interface, 'vlan':gts_port.value} )
                commands.append( COMMAND_SET_VLAN_ENCAP % {'port':gts_port.port.interface, 'vlan':gts_port.value} )
                commands.append( COMMAND_SET_VLAN_ID % {'port':gts_port.port.interface, 'vlan':gts_port.value} )
                commands.append( COMMAND_SET_SWAP_PUSH_POP % {'port':gts_port.port.interface, 'vlan':gts_port.value} )

        for gts_port in self.src_port,self.dest_port:
            commands.append( COMMAND_LOCAL_CONNECTIONS % { 'switch':switch_name, 
                                                       'interface':"%s" % gts_port.port.interface,
                                                       'subinterface': "%s" % gts_port.value if
                                                       gts_port.port.label.type_ == "vlan" else '0' } )
        return commands


    def _generateLocalConnectionDeActivate(self):
        commands = []
        switch_name = self._createSwitchName( self.connection_id )

        for gts_port in self.src_port,self.dest_port:
            #if gts_port.port.label.type_ == "port":
             #   commands.append( COMMAND_DELETE_INTERFACES % { 'port':gts_port.port.interface } )
            if gts_port.port.label is not None and gts_port.port.label.type_ == "vlan":
                commands.append( COMMAND_DELETE_INTERFACES_VL % { 'port':gts_port.port.interface, 'vlan' : "%s"
                    % gts_port.value})
        commands.append( COMMAND_DELETE_CONNECTIONS % { 'switch':switch_name } )

        return commands
