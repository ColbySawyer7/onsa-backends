"""
OpenNSA JUNOS MX backend
Currently only mpls, vlan and full port connections are supported

Author: Henrik Thostup Jensen < htj at nordu dot net >
Author: Tamas Varga <vargat(at)niif(dot)hu>
Author: Michal Hazlinsky <hazlinsky(at)cesnet(dot)cz>
Author: Jan von Oorschot <janvonoorschot(at)google(dot)com>


This backend expects some mandatory global configuration on the router as well
as some sattically placed statements on interfaces involved dynamic circuits provisioning. 

TODO: describe the expected configuration
"""

import random

from twisted.python import log
from twisted.internet import defer

from opennsa import constants as cnt, config
from opennsa.backends.common import genericbackend, ssh

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import *
from lxml import etree

# Common commands for Junos

INTERFACE_PORT = '''
<interfaces>
    <interface>
        <name>%(port)s</name>
            <encapsulation>ethernet-ccc</encapsulation>
            <mtu>9000</mtu>
            <unit>
                <name>0</name>
                <description>%(description)s</description>
                <family>
                    <ccc>
                    </ccc>
                </family>
            </unit>
    </interface>
</interfaces>
'''

INTERFACE_PORT_PTRN = '<interfaces><interface><name>%(port)s</name><unit><name>0</name></unit></interface></interfaces>'

INTERFACE_VLAN = '''
<interfaces>
    <interface>
        <name>%(port)s</name>
        <unit>
            <name>%(vlan)s</name>
            <description>%(description)s</description>
            <encapsulation>vlan-ccc</encapsulation>
            <vlan-id>%(vlan)s</vlan-id>
            <input-vlan-map>
                <pop/>
            </input-vlan-map>
            <output-vlan-map>
                <push/>
            </output-vlan-map>
        </unit>
    </interface>
</interfaces>
'''

INTERFACE_VLAN_PTRN = '<interfaces><interface><name>%(port)s</name><unit><name>%(vlan)s</name></unit></interface></interfaces>'

INT_SWITCH = '''
<protocols>
    <connections>
        <interface-switch>
            <name>%(switch)s</name>
            <interface>
                <name>%(interface)s.%(subinterface)s</name>
            </interface>
        </interface-switch>
    </connections>
</protocols>
'''

L2_CIRCUIT = lambda id : f'''
<protocols>
    <l2circuit>
        <neighbor>
            <name>%(remote_ip)s</name>
            <interface>
                <name>%(port)s</name>
                <virtual-circuit-id>{id}%(unique-id)s</virtual-circuit-id>
                <description>%(description)s</description>
                <no-control-word/>
                <ignore-mtu-mismatch/>
            </interface>
        </neighbor>
    </l2circuit>
</protocols>
'''

DEL_INTERFACE_PORT = '''
<interfaces>
    <interface operation="delete">
        <name>%(port)s</name>
    </interface>
</interfaces>
'''

DEL_INTERFACE_VLAN = '''
<interfaces>
    <interface>
        <name>%(port)s</name>
        <unit operation="delete">
            <name>%(vlan)s</name>
        </unit>
    </interface>
</interfaces>
'''


DEL_INT_SWITCH = '''
<protocols>
    <connections>
        <interface-switch operation="delete">
            <name>%(switch)s</name>
        </interface-switch>
    </connections>
</protocols>
'''

DEL_L2_CIRCUIT = '''
<protocols>
    <l2circuit>
        <neighbor>
            <name>%(remote_ip)s</name>
            <interface operation="delete">
                <name>%(port)s</name>
            </interface>
        </neighbor>
    </l2circuit>
</protocols>
'''

LOG_SYSTEM = 'Backend: JUNOS MX NETCONF: '

class JUNOSCommandSender:

    def __init__(self, host, port, ssh_host_fingerprint, user, ssh_public_key_path, ssh_private_key_path,
            junos_routers,network_name, enableqos, descriptions, vc_id_prefix):
        self.netconf_device = Device(host=host, port=port, user=user, ssh_private_key_file=ssh_private_key_path)
        self.junos_routers = junos_routers
        self.network_name = network_name
        self.enableqos = enableqos
        self.descriptions = descriptions
        self.logsys = LOG_SYSTEM + network_name
        self.sem = defer.DeferredSemaphore(1)
        self.vc_id_prefix = vc_id_prefix

    @defer.inlineCallbacks
    def _sendCommands(self, commands, patterns=[]):
        yield self.sendCom(commands, patterns)

    @defer.inlineCallbacks
    def setupLink(self, connection_id, source_port, dest_port, bandwidth):
        conn = yield genericbackend.GenericBackendConnections.find(where=['connection_id = ?', connection_id], limit=1)
        args = vars(conn)
        descriptions = self.descriptions.format(**args)
        descriptions = self.cleanup_string(descriptions)
        cg = JUNOSCommandGenerator(connection_id,source_port,dest_port,self.junos_routers,self.network_name,bandwidth,self.enableqos,descriptions, vc_id_prefix=self.vc_id_prefix)
        commands, patterns = cg.generateActivateCommand() 
        result = yield self.sem.run(self._sendCommands, commands, patterns)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def teardownLink(self, connection_id, source_port, dest_port, bandwidth):
        conn = yield genericbackend.GenericBackendConnections.find(where=['connection_id = ?', connection_id], limit=1)
        args = vars(conn)
        descriptions = self.descriptions.format(**args)
        cg = JUNOSCommandGenerator(connection_id,source_port,dest_port,self.junos_routers,self.network_name,bandwidth,self.enableqos,descriptions, vc_id_prefix=self.vc_id_prefix)
        commands = cg.generateDeactivateCommand() 
        result = yield self.sem.run(self._sendCommands, commands)
        defer.returnValue(result)

    def cleanup_string(self, str):
        result = str
        for i in ['?', '\"', '\'']:
            result = result.replace(i, '')
        return result.strip()
    
    def sendCom(self, commands, patterns):
        try:
            log.msg('Opening connection...', debug=True, system=self.logsys)
            self.netconf_device.open()

            if (len(patterns) > 0):
                log.msg('Checking interfaces before config...', debug=True, system=self.logsys)
                for pattern in patterns:
                    int_config = self.netconf_device.rpc.get_config(filter_xml=pattern, options={'inherit':'inherit'})
                    if (len(int_config) > 0):
                        log.msg('--- ERROR: Something found on the given interface! Configuration canceled. :: %s' % (etree.tostring(int_config, encoding='unicode', pretty_print=True)), debug=True, system=self.logsys)
                        raise Exception("Something found on the given interface! Configuration canceled.") 
                        

            with Config(self.netconf_device, mode='private') as dev_private:  # Lets go to edit private mode
                
                for command in commands:
                    log.msg('--- Loading in configuration: %s' % (command), debug=True, system=self.logsys)
                    res = dev_private.load(command)
                
                log.msg('--- Changes applied: \n %s' % (dev_private.diff()), debug=True, system=self.logsys)
                                
                # Lets do commit check 
                coomit_check_result = False
                coomit_check_result = dev_private.commit_check()
                # If check is OK ... lets commit
                if coomit_check_result:
                    log.msg('Commiting config...', debug=True, system=self.logsys)
                    res = dev_private.commit(comment='OpenNSA_link_setup', timeout=90)

        except ConnectError as err:
            log.msg("Cannot connect to device: {0}".format(err), system=self.logsys)
            raise err
        except CommitError as err:
            log.msg("Commit check failed, rolling back ::  {0}".format(err), system=self.logsys)
            raise err
        except Exception as err:
            log.msg("Failed to send commands :: {0}".format(err), system=self.logsys)
            raise err
        finally:
            self.netconf_device.close()

class JUNOSTarget(object):

    def __init__(self, port, original_port,value=None):
        self.port = port
        self.value = value
        self.original_port = original_port

    def __str__(self):
        if self.port.remote_network is None:
            if self.port.label is not None:
                return 'JUNOSTarget&%s&%s&%s&%s&' % (self.original_port,self.port.interface,self.port.label.type_,self.value)
            else:
                return 'JUNOSTarget&%s&%s&&&' % (self.original_port,self.port.interface)
        else:
            if self.port.label is not None:
                return 'JUNOSTarget&%s&%s&%s&%s&%s' % (self.original_port,self.port.interface,self.port.label.type_,self.value,self.port.remote_port)
            else:
                return 'JUNOSTarget&%s&%s&&&%s' % (self.original_port,self.port.interface,self.port.remote_port)


class JUNOSConnectionManager:

    def __init__(self, port_map, host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
            junos_routers,network_name, enableqos, descriptions, vc_id_prefix):
        self.network_name = network_name
        self.port_map = port_map
        self.command_sender = JUNOSCommandSender(host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
                junos_routers,network_name, enableqos, descriptions, vc_id_prefix)
        self.junos_routers = junos_routers
        self.logsys = LOG_SYSTEM + network_name
        self.supportedLabelPairs = {
                "mpls" : ['vlan','port'],
                "vlan" : ['port','mpls'],
                "port" : ['vlan','mpls']
        }

    def getResource(self, port, label):
        assert label is None or label.type_ in (cnt.MPLS, cnt.ETHERNET_VLAN), 'Label must be None or VLAN or MPLS'
        val = "" if label is None else str(label.labelValue())
        return port + ':' + val
# TODO : modify the delimiter ":" to something else ... since ":" can be part of interafce name in JUNOS when break out cable is used on the physical port 

    def getTarget(self, port, label):
        if label is None:
            return JUNOSTarget(self.port_map[port], port)
        else:
            return JUNOSTarget(self.port_map[port], port, label.labelValue())

    def createConnectionId(self, source_target, dest_target):
        return 'JUNOS-' + str(random.randint(100000,999999))

    def canSwapLabel(self, label_type):
        return True

    def setupLink(self, connection_id, source_target, dest_target, bandwidth):
        def linkUp(_):
            log.msg('Link %s -> %s up' % (source_target, dest_target), system=self.logsys)
        d = self.command_sender.setupLink(connection_id,source_target, dest_target,bandwidth)
        d.addCallback(linkUp)
        return d

    def teardownLink(self, connection_id, source_target, dest_target, bandwidth):
        def linkDown(_):
            log.msg('Link %s -> %s down' % (source_target, dest_target), system=self.logsys)
        d = self.command_sender.teardownLink(connection_id,source_target, dest_target, bandwidth)
        d.addCallback(linkDown)
        return d

    def canConnect(self, source_port, dest_port, source_label, dest_label):
        src_label_type = 'port' if source_label is None else source_label.type_
        dst_label_type = 'port' if dest_label is None else dest_label.type_
        #by default, acccept same types
        if src_label_type == dst_label_type:
            return True
        elif src_label_type in self.supportedLabelPairs and dst_label_type in self.supportedLabelPairs[src_label_type]:
            return True
        else: 
            return False


def JUNOSMXBackend(network_name, nrm_ports , parent_requester, cfg):

    name = 'JUNOS_MX_NETCONF'
    nrm_map  = dict( [ (p.name, p) for p in nrm_ports ] ) # for the generic backend
    port_map = dict( [ (p.name, p) for p in nrm_ports ] ) # for the nrm backend

    host             = cfg[config.JUNOS_HOST]
    port             = cfg.get(config.JUNOS_PORT, 22)
    host_fingerprint = cfg[config.JUNOS_HOST_FINGERPRINT]
    user             = cfg[config.JUNOS_USER]
    ssh_public_key   = cfg[config.JUNOS_SSH_PUBLIC_KEY]
    ssh_private_key  = cfg[config.JUNOS_SSH_PRIVATE_KEY]
    enableqos = cfg.get(config.JUNOS_ENABLE_QOS, False)
    descriptions = cfg.get(config.JUNOS_DESCRIPTIONS, "OpenNSA_Link")
    logsys = LOG_SYSTEM + network_name
    vc_id_prefix = cfg[config.JUNOS_VC_ID_BASE]


    if enableqos == 'true':
        enableqos = True
    else:
        enableqos = False
    junos_routers_c    =  cfg.get(config.JUNOS_ROUTERS, "").split()
    has_mpls = False
    for port_mpls in port_map:        
        if  port_map[port_mpls].label is not None :
            if port_map[port_mpls].label.type_ == "mpls":
                has_mpls = True  
    if len(junos_routers_c) > 0:
        junos_routers = dict()
        log.msg("Loaded JUNOS MX netconf backend with routers:", debug=True, system=logsys)
        for g in junos_routers_c:
            r,l = g.split('@',1)
            log.msg("Network: %s loopback: %s" % (r,l), debug=True, system=logsys)
            junos_routers[r] = l
    elif has_mpls == True :
        raise Exception("Has MPLS ports, but list of router with loopback IPs is not provided.")
    else:
        log.msg("Loaded JUNOS MX netconf backend with no mpls ports.", debug=True, system=logsys)
        junos_routers = dict()
    log.msg('Loaded JUNOS MX netconf backend with enableqos=%s and descriptions=%s'% (enableqos,descriptions), debug=True, system=logsys)
    cm = JUNOSConnectionManager(port_map, host, port, host_fingerprint, user, ssh_public_key, ssh_private_key,
            junos_routers,network_name, enableqos, descriptions, vc_id_prefix)
    return genericbackend.GenericBackend(network_name, nrm_map, cm, parent_requester, name)

class JUNOSCommandGenerator(object):

    def __init__(self,connection_id,src_port,dest_port,junos_routers,network_name,bandwidth=None,enableqos=False,descriptions="NSI", vc_id_prefix=40000):
        self.connection_id = connection_id
        self.src_port = src_port
        self.dest_port = dest_port
        self.bandwidth = bandwidth
        self.junos_routers = junos_routers
        self.network_name = network_name
        self.descriptions = descriptions
        self.logsys = LOG_SYSTEM + network_name
        self.vc_id_prefix = vc_id_prefix
        if enableqos and self.bandwidth>0:
            self.usebandwidth = True
        else:
            self.usebandwidth = False
        log.msg('Initialised command generator with parameters--> src: %s | dst: %s | bandwidth: %s | connectionID: %s' %
                (src_port,dest_port,bandwidth,connection_id), debug=True, system=self.logsys)

    def generateActivateCommand(self):
        commands = []
        patterns = []
        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("Generating activate commands between %s and %s " %  (self.src_port,self.dest_port), debug=True, system=self.logsys)

        
        if source_port.remote_network is None and dest_port.remote_network is None:
            commands, patterns = self._generateLocalConnectionActivate()
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            commands, patterns = self._generateTransitConnectionActivate()
        else: 
            commands, patterns = self._generateRemoteConnectionActivate()

        return commands, patterns


    def generateDeactivateCommand(self):
        commands = {}
        source_port = self.src_port.port
        dest_port   = self.dest_port.port
        log.msg("Generating deactivate commands between %s and %s " %  (self.src_port,self.dest_port), debug=True, system=self.logsys)

        if source_port.remote_network is None and dest_port.remote_network is None:
            commands = self._generateLocalConnectionDeActivate()
        elif source_port.remote_network is not None and dest_port.remote_network is not None:
            commands = self._generateTransitConnectionDeactivate()
        else: 
            commands = self._generateRemoteConnectionDeactivate()

        return commands

    def _createSwitchName(self,connection_id):
        switch_name = 'NSI-%s' % (connection_id)

        return switch_name

    def _generateLocalConnectionActivate(self):
        commands = []
        patterns = []
        switch_name = self._createSwitchName( self.connection_id )
        burstsize = (self.bandwidth * 5 * 1000) / 8
        bwidth = self.bandwidth * 1000000
        # For configuration reason, we're going to generate port things first, then the interface-switch commands
        for junos_port in self.src_port,self.dest_port:
            if junos_port.port.label is None:
                commands.append( INTERFACE_PORT % { 'port':junos_port.port.interface, 'description':self.descriptions} )
                patterns.append( INTERFACE_PORT_PTRN % { 'port':junos_port.port.interface} )
            elif junos_port.port.label.type_ == "vlan":
                commands.append( INTERFACE_VLAN % {'port':junos_port.port.interface, 'vlan':junos_port.value, 'description':self.descriptions} )
                patterns.append( INTERFACE_VLAN_PTRN % {'port':junos_port.port.interface, 'vlan':junos_port.value} )

        for junos_port in self.src_port,self.dest_port:
            commands.append( INT_SWITCH % { 'switch':switch_name, 
                                                       'interface':"%s" % junos_port.port.interface,
                                                       'subinterface': "%s" % junos_port.value if
                                                       junos_port.port.label is not None else '0' } )
        return commands, patterns

    def _generateLocalConnectionDeActivate(self):
        commands = []
        switch_name = self._createSwitchName( self.connection_id )

        for junos_port in self.src_port,self.dest_port:
            if junos_port.port.label is None:
                commands.append( DEL_INTERFACE_PORT % { 'port':junos_port.port.interface } )
            elif junos_port.port.label.type_ == "vlan":
                commands.append( DEL_INTERFACE_VLAN % { 'port':junos_port.port.interface, 'vlan' : "%s"
                    % junos_port.value})
        commands.append( DEL_INT_SWITCH % { 'switch':switch_name } )

        return commands

    def _generateRemoteConnectionActivate(self):
        commands = []
        patterns = []
        local_port = self.src_port if self.src_port.port.remote_network is None else self.dest_port
        remote_port = self.src_port if self.src_port.port.remote_network is not None else self.dest_port
        burstsize = (self.bandwidth * 5 * 1000) / 8
        bwidth = self.bandwidth * 1000000
        unq_id = int(remote_port.value) + 10000

        log.msg("Local port is: %s | at %s " % (local_port.original_port, local_port.port.interface), debug=True, system=self.logsys )
        log.msg("Remote port is: %s | at %s " % (remote_port.original_port, remote_port.port.interface), debug=True, system=self.logsys )

        if local_port.port.label is None:
            commands.append( INTERFACE_PORT % { 'port':local_port.port.interface, 'description':self.descriptions} )
            patterns.append( INTERFACE_PORT_PTRN % { 'port':local_port.port.interface} )
        elif local_port.port.label.type_ == "vlan":
            commands.append( INTERFACE_VLAN % {'port':local_port.port.interface, 'vlan':local_port.value, 'description':self.descriptions} )
            patterns.append( INTERFACE_VLAN_PTRN % {'port':local_port.port.interface, 'vlan':local_port.value} )

        if remote_port.port.label is not None and remote_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(remote_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name) 
            if local_port.port.label is None:
                commands.append(L2_CIRCUIT(self.vc_id_prefix) % { 'remote_ip':remote_sw_ip,
                                                        'port' : local_port.port.interface+".0", 'unique-id' : unq_id, 'description':self.descriptions
                                                        } )
            elif local_port.port.label.type_ == "vlan":
                 commands.append(L2_CIRCUIT(self.vc_id_prefix) % { 'remote_ip':remote_sw_ip,
                                                        'port' : local_port.port.interface + "." + str(local_port.value), 'unique-id' : unq_id, 'description':self.descriptions
                                                        } )

        if remote_port.port.label is not None and remote_port.port.label.type_ == "vlan":
            switch_name = self._createSwitchName( self.connection_id )

            commands.append( INTERFACE_VLAN % {'port':remote_port.port.interface, 'vlan':remote_port.value, 'description':self.descriptions} )
            patterns.append( INTERFACE_VLAN_PTRN % {'port':local_port.port.interface, 'vlan':local_port.value} )
            for junos_port in local_port,remote_port:
                commands.append( INT_SWITCH % { 'switch':switch_name, 
                                                       'interface':"%s" % junos_port.port.interface,
                                                       'subinterface': "%s" % junos_port.value if
                                                       junos_port.port.label.type_ == "vlan" else '0' } )
        return commands, patterns

    def _generateRemoteConnectionDeactivate(self):
        commands = []
        local_port = self.src_port if self.src_port.port.remote_network is None else self.dest_port
        remote_port = self.src_port if self.src_port.port.remote_network is not None else self.dest_port

        if local_port.port.label is None:
            commands.append( DEL_INTERFACE_PORT % { 'port':local_port.port.interface } )
        elif local_port.port.label.type_ == "vlan":
            commands.append( DEL_INTERFACE_VLAN % { 'port':local_port.port.interface, 'vlan' : "%s"
                % local_port.value})

        if remote_port.port.label is not None and remote_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(remote_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name)
            if local_port.port.label is None:
                commands.append( DEL_L2_CIRCUIT % { 'remote_ip' : remote_sw_ip, 'port' : local_port.port.interface+".0"} )
            elif local_port.port.label.type_ == "vlan":
                commands.append( DEL_L2_CIRCUIT % { 'remote_ip' : remote_sw_ip, 'port' : local_port.port.interface + "." + str(local_port.value) } )

        elif remote_port.port.label.type_ == "vlan":
            switch_name = self._createSwitchName( self.connection_id )
            commands.append( DEL_INTERFACE_VLAN % { 'port':remote_port.port.interface, 'vlan' : "%s"
                % remote_port.value})
            commands.append( DEL_INT_SWITCH % { 'switch':switch_name } )

        return commands

    def _generateTransitConnectionActivate(self):
        commands = []
        patterns = []
        local_port = self.src_port
        remote_port = self.dest_port
        log.msg("%s" % local_port.original_port)
        log.msg("%s" % remote_port.original_port)
        burstsize = (self.bandwidth * 5 * 1000) / 8 
        bwidth = self.bandwidth * 1000000

        if local_port.port.label is not None and local_port.port.label.type_ == "vlan":
            commands.append( INTERFACE_VLAN % {'port':local_port.port.interface, 'vlan':local_port.value, 'description':self.descriptions} )
            patterns.append( INTERFACE_VLAN_PTRN % {'port':local_port.port.interface, 'vlan':local_port.value} )
        if remote_port.port.label is not None and remote_port.port.label.type_ == "vlan":
            commands.append( INTERFACE_VLAN % {'port':remote_port.port.interface, 'vlan':remote_port.value, 'description':self.descriptions} )
            patterns.append( INTERFACE_VLAN_PTRN % {'port':local_port.port.interface, 'vlan':local_port.value} )
        if local_port.port.label is not None and local_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(local_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name)
            unq_id = int(local_port.value) + 10000 
            if remote_port.port.label is not None and remote_port.port.label.type_ == "vlan":
                commands.append(L2_CIRCUIT(self.vc_id_prefix) % { 'remote_ip':remote_sw_ip,
                                                        'port' : remote_port.port.interface + "." + str(remote_port.value), 'unique-id' : unq_id, 'description':self.descriptions
                                                        } )
        if remote_port.port.label is not None and remote_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(remote_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name)
            unq_id = int(remote_port.value) + 10000 
            if local_port.port.label is not None and local_port.port.label.type_ == "vlan":
                commands.append(L2_CIRCUIT(self.vc_id_prefix) % { 'remote_ip':remote_sw_ip,
                                                        'port' : local_port.port.interface + "." + str(local_port.value), 'unique-id' : unq_id, 'description':self.descriptions
                                                        } )
        if remote_port.port.label is not None and remote_port.port.label.type_ == "vlan" and local_port.port.label is not None and local_port.port.label.type_ == "vlan":
            switch_name = self._createSwitchName( self.connection_id )
            for junos_port in local_port,remote_port:
                commands.append( INT_SWITCH % { 'switch':switch_name, 
                                                       'interface':"%s" % junos_port.port.interface,
                                                       'subinterface': "%s" % junos_port.value if
                                                       junos_port.port.label.type_ == "vlan" else '0' } )
        #TODO
        # we're missing 2 things here
        # mpls->mpls lsp stiching
        # port->something else crossconnect
        return commands, patterns

    def _generateTransitConnectionDeactivate(self):
        commands = []
        local_port = self.src_port 
        remote_port = self.dest_port

        if local_port.port.label is not None and local_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(local_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name)
            commands.append( DEL_L2_CIRCUIT % { 'remote_ip' : remote_sw_ip, 'port' : remote_port.port.interface + "." + str(remote_port.value) } )

        if local_port.port.label is not None and local_port.port.label.type_ == "vlan":
            switch_name = self._createSwitchName( self.connection_id )
            commands.append( DEL_INTERFACE_VLAN % { 'port':local_port.port.interface, 'vlan' : "%s"
                % local_port.value})

        if remote_port.port.label is not None and remote_port.port.label.type_ == "mpls":
            remote_sw_ip = self._getRouterLoopback(remote_port.port.remote_network)
            local_sw_ip = self._getRouterLoopback(self.network_name)
            commands.append( DEL_L2_CIRCUIT % { 'remote_ip' : remote_sw_ip, 'port' : local_port.port.interface + "." + str(local_port.value) } )

        if remote_port.port.label is not None and remote_port.port.label.type_ == "vlan":
            switch_name = self._createSwitchName( self.connection_id )
            commands.append( DEL_INTERFACE_VLAN % { 'port':remote_port.port.interface, 'vlan' : "%s"
                % remote_port.value})

        if local_port.port.label is not None and remote_port.port.label is not None:
            if remote_port.port.label.type_ == "vlan" and local_port.port.label.type_ == "vlan":
                commands.append( DEL_INT_SWITCH % { 'switch':switch_name } )
        
        return commands

    def _getRouterLoopback(self,network_name):
        # if ":topology" in network_name:
        #     network_name = network_name.replace(":topology","")
        if network_name in self.junos_routers:
            return self.junos_routers[network_name]
        else:
           raise Exception("Can't find loopback IP address for network %s " % network_name)
