"""
Backend for Juniper Junos SPACE CSD plugin.

Author: Michal Hazlinsky <hazlinsky at cesnet.cz>

Backend specific configuraton: 

space_user=USERNAME
space_password=SECRET_PASSWD
space_api_url=BASE_URL
csd_service_def=SERVICE_DEF_ID_TO_USE # from your CSD insatnce
csd_customer_id=CUSTOMER_ID_TO_USE # from your CSD instance
routers=ROUTER1_NAME@ROUTER1_ID
 ROUTER2_NAME@ROUTER2_ID

"""

import base64
import random
import time

from twisted.python import log
from twisted.web.error import Error as WebError
from twisted.internet.ssl import ClientContextFactory


from opennsa import constants as cnt, config
from opennsa.backends.common import genericbackend
from opennsa.protocols.shared import httpclient

from lxml import etree

CSD_TIMEOUT = 60 # ncs typically spends 25-32 seconds creating/deleting a vpn, sometimes a bit more

# NO_OUT_OF_SYNC_CHECK = 'no-out-of-sync-check' # put this as a query parameter to get ncs to bypass the check

URI_CREATE_ORDER="api/space/nsas/eline-ptp/service-management/service-orders/"
URI_GET_SERVICES="api/space/nsas/eline-ptp/service-management/services"
URI_DELETE_SERVICE="api/space/nsas/eline-ptp/service-management/services/%(service_id)s"

ORDER_PAYLOAD = """
<Data xmlns="services.schema.networkapi.jmp.juniper.net">
<ServiceResource>
	<ServiceOrder>
		<Common>
			<Name>%(service_name)s</Name>
			<Comments>%(description)s</Comments>
		</Common>
		<ServiceEndPointGroup>
			<DeviceInfo>
				<NA>
					<DeviceName>%(router_a_name)s</DeviceName>
					<DeviceID>%(router_a_id)s</DeviceID>
				</NA>
			</DeviceInfo>
			<ServiceEndPoint>
				<InterfaceName>%(interface_a)s</InterfaceName>
				<ServiceEndpointConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"	xsi:type="PTPElineLDPEndPointConfigParameterOrderType">
					<EndPointCategory>PTP</EndPointCategory>
                    <TrafficType>DOT1Q Transport single vlan</TrafficType>
                    <EthernetOption>dot1q</EthernetOption>
                    <UnitId>%(vlan_a)s</UnitId>
					<VlanId>%(vlan_a)s</VlanId>
				</ServiceEndpointConfiguration>
			</ServiceEndPoint>
		</ServiceEndPointGroup>
		<ServiceEndPointGroup>
			<DeviceInfo>
				<NA>
					<DeviceName>%(router_b_name)s</DeviceName>
					<DeviceID>%(router_b_id)s</DeviceID>
				</NA>
			</DeviceInfo>
			<ServiceEndPoint>
				<InterfaceName>%(interface_b)s</InterfaceName>
				<ServiceEndpointConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"	xsi:type="PTPElineLDPEndPointConfigParameterOrderType">
					<EndPointCategory>PTP</EndPointCategory>
                    <TrafficType>DOT1Q Transport single vlan</TrafficType>
                    <EthernetOption>dot1q</EthernetOption>
                    <UnitId>%(vlan_a)s</UnitId>
					<VlanId>%(vlan_b)s</VlanId>
				</ServiceEndpointConfiguration>
			</ServiceEndPoint>
		</ServiceEndPointGroup>
		<ServiceOrderParameter xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="PTPConfigParameterOrderType">
		</ServiceOrderParameter>
		<Reference>
		<Customer key="%(cus_key)s"/>
		<ServiceDefinition>
			<ServiceDefinitionID key="%(service_def_id)s"/>
		</ServiceDefinition>
		</Reference>
	</ServiceOrder>
</ServiceResource>
		<CustomAction xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ServiceOrderCustomActionType">
		<Action>SaveAndDeployNow</Action>
		</CustomAction>
</Data>
"""


LOG_SYSTEM = 'JUNOS.CSD'

class JUNOSSPACERouter(object):
    def __init__(self,router_name,router_id):
        self.router_name = router_name
        self.router_id = router_id

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "Router name {} deviceId {} ".format(self.router_name,self.router_id)


class CSDTarget(object):

    def __init__(self, router, interface, vlan=None):
        self.router = router
        self.interface = interface
        self.vlan = vlan

    def __str__(self):
        if self.vlan:
            return '<CSDTarget %s/%s#%i>' % (self.router, self.interface, self.vlan)
        else:
            return '<CSDTarget %s/%s>' % (self.router, self.interface)



def createCSDPayload(connection_id, source_target, dest_target, service_def_id, cus_id, space_routers, csd_descriptions):

    intps = {
        'service_name'  : connection_id,
        'router_a_name'      : source_target.router,
        'router_a_id'   : space_routers[source_target.router].router_id,
        'interface_a'      : source_target.interface,
        'router_b_name'   : dest_target.router,
        'router_b_id'  : space_routers[dest_target.router].router_id,
        'interface_b'  : dest_target.interface,
        'cus_key'  : cus_id,
        'service_def_id'  : service_def_id
    }

    timestamp = str(time.time()).split(".", 1)[0]
    intps['description'] = csd_descriptions + " " + source_target.router + "." + dest_target.router + "." + timestamp + " OpenNSA build"
    intps['vlan_a'] = source_target.vlan
    intps['vlan_b'] = dest_target.vlan
    payload = ORDER_PAYLOAD % intps
    log.msg("Payload created: \n {}".format(payload),debug=True,system=LOG_SYSTEM)

    return payload



def _extractErrorMessage(failure):
    # used to extract error messages from http requests
    if isinstance(failure.value, WebError):
        return failure.value.response
    else:
        return failure.getErrorMessage()


class WebClientContextFactory(ClientContextFactory):
    def getContext(self):
        return ClientContextFactory.getContext(self)


class CSDConnectionManager:

    def __init__(self, port_map, space_user, space_password, space_api_url, space_routers, csd_service_def, csd_customer_id, network_name, csd_descriptions):
        self.network_name = network_name
        self.port_map = port_map
        self.space_user=space_user
        self.space_password=space_password
        self.space_api_url=space_api_url
        self.space_routers = space_routers
        self.csd_service_def = csd_service_def
        self.csd_customer_id = csd_customer_id
        self.csd_descriptions = csd_descriptions
    

    def getResource(self, port, label):
        assert label is None or label.type_ == cnt.ETHERNET_VLAN, 'Label must be None or VLAN'
        val = "" if label is None else str(label.labelValue())
        return port + ':' + val # port contains router and port


    def getTarget(self, port, label):
        assert label is None or label.type_ == cnt.ETHERNET_VLAN, 'Label must be None or VLAN'
        if label is not None and label.type_ == cnt.ETHERNET_VLAN:
            vlan = int(label.labelValue())
            assert 1 <= vlan <= 4095, 'Invalid label value for vlan: %s' % label.labelValue()
        else:
            vlan = None

        ri = self.port_map[port]
        router, interface = ri.split(':')
        return CSDTarget(router, interface, vlan)


    def createConnectionId(self, source_target, dest_target):
        return 'ON-' + str(random.randint(100000,999999))


    def canSwapLabel(self, label_type):
        return True


    def _createAuthzHeader(self):
        credentials = self.space_user + ":" + self.space_password
        cr = base64.b64encode(credentials.encode("utf-8"))
        cred = "Basic " + cr.decode("utf-8")
        
        return cred

    def _createHeaders(self):
        headers = {}
        #TODO> set propper data type -- done
        headers["Content-Type"] = "application/vnd.net.juniper.space.service-management.service-order+xml;version=2;charset=UTF-8"
        headers["Authorization"] = self._createAuthzHeader()
        return headers

    def setupLink(self, connection_id, source_target, dest_target, bandwidth):
        payload = createCSDPayload(connection_id, source_target, dest_target, self.csd_service_def, self.csd_customer_id, self.space_routers, self.csd_descriptions)
        headers = self._createHeaders()
        contextFactory = WebClientContextFactory()

        def linkUp(data):
            log.msg('Link %s -> %s up' % (source_target, dest_target), system=LOG_SYSTEM)
            log.msg('Response: \n %s ' % (data),debug=True, system=LOG_SYSTEM)

        def error(failure):
            log.msg('Error bringing up link %s -> %s' % (source_target, dest_target), system=LOG_SYSTEM)
            log.msg('Message: %s' % _extractErrorMessage(failure), system=LOG_SYSTEM)
            return failure
        
        spaceurl=self.space_api_url + URI_CREATE_ORDER  
        d = httpclient.httpRequest(spaceurl, payload.encode(), headers, method=b'POST', timeout=CSD_TIMEOUT, ctx_factory=contextFactory)
        d.addCallbacks(linkUp, error)
        return d


    def teardownLink(self, connection_id, source_target, dest_target, bandwidth):
        headers = {}
        headers["Accept"] = "*/*"
        headers["Authorization"] = self._createAuthzHeader()
        serviceID = None
        contextFactory = WebClientContextFactory()

        def linkDown(data):
            log.msg('Link %s -> %s down' % (source_target, dest_target), system=LOG_SYSTEM)
            log.msg('Response: \n %s ' % (data),debug=True, system=LOG_SYSTEM)

        def error(failure):
            log.msg('Error bringing down link %s -> %s' % (source_target, dest_target), system=LOG_SYSTEM)
            log.msg('Message from Get Service ID: %s' % _extractErrorMessage(failure), system=LOG_SYSTEM)
            return failure

        def doServiceDelete(data):
            headers = {}
            #headers["Content-Type"] = "application/vnd.net.juniper.space.service-management.service-order+xml;version=2;charset=UTF-8"
            headers["Authorization"] = self._createAuthzHeader()
            contextFactory = WebClientContextFactory()
            serviceID = 0
            nsmap={'a': 'services.schema.networkapi.jmp.juniper.net'}
            services = etree.fromstring(data).xpath("/a:Data/a:ServiceResource/a:Service", namespaces=nsmap)
            for service in services :
                if service.xpath("a:Common/a:Name", namespaces=nsmap)[0].text == connection_id:
                    serviceID = service.xpath("a:Common/a:Identity", namespaces=nsmap)[0].text
            if serviceID is 0 :
                raise Exception("Can't find service ID for connection %s " % connection_id) 
            log.msg('Link %s -> %s Call for DELETE. Service ID: %s' % (source_target, dest_target, serviceID), system=LOG_SYSTEM)
            
            spaceurl=self.space_api_url + URI_DELETE_SERVICE % {'service_id': serviceID}
            d = httpclient.httpRequest(spaceurl, b'', headers, method=b'DELETE', timeout=CSD_TIMEOUT, ctx_factory=contextFactory)
            return d

        def errorSerDel(failure):
            log.msg('Error bringing down link %s -> %s' % (source_target, dest_target), system=LOG_SYSTEM)
            log.msg('Message from Service delete: %s' % _extractErrorMessage(failure), system=LOG_SYSTEM)
            return failure

        spaceurl=self.space_api_url + URI_GET_SERVICES
        # spaceurl = self.space_api_url + "api/space/nsas/eline-ptp/service-management/services/32440380"
        res = httpclient.httpRequest(spaceurl, b'', headers, method=b'GET', timeout=CSD_TIMEOUT, ctx_factory=contextFactory)
        res.addCallbacks(doServiceDelete, error)
        res.addCallbacks(linkDown, errorSerDel)

        

        #TODO: set up propper URL for delete  application/vnd.net.juniper.space.service-management.service+xml
        #d = httpclient.httpRequest(self.space_api_url, None, headers, method='DELETE', timeout=CSD_TIMEOUT)
        #d.addCallbacks(linkDown, error)
        return res


def JunosCSDBackend(network_name, nrm_ports, parent_requester, cfg): 

    name = 'CSD %s' % network_name
    nrm_map  = dict( [ (p.name, p) for p in nrm_ports ] ) # for the generic backend
    port_map = dict( [ (p.name, p.interface) for p in nrm_ports ] ) # for the nrm backend

    # extract config items
    space_user      = cfg[config.SPACE_USER]
    space_password  = cfg[config.SPACE_PASSWORD]
    space_api_url   = cfg[config.SPACE_API_URL]
    space_routers_config   = cfg[config.SPACE_ROUTERS].split()
    csd_service_def = cfg[config.CSD_SERVICE_DEF]
    csd_customer_id = cfg[config.CSD_CUSTOMER_ID]
    csd_descriptions = cfg.get(config.JUNOS_DESCRIPTIONS, "OpenNSA")
    

    space_routers = dict()
    log.msg("Loaded JunosCSD backend with routers:")
    for g in space_routers_config:
        r,n = g.split('@',1)
        junosspace_router = JUNOSSPACERouter(r,n)
        log.msg("%s" % (junosspace_router))
        space_routers[r] = junosspace_router

    # csd_services_url = str(cfg[config.NCS_SERVICES_URL]) # convert from unicode
    # user             = cfg[config.NCS_USER]
    # password         = cfg[config.NCS_PASSWORD]

    cm = CSDConnectionManager(port_map, space_user,space_password,space_api_url,space_routers, csd_service_def, csd_customer_id, network_name, csd_descriptions)
    return genericbackend.GenericBackend(network_name, nrm_map, cm, parent_requester, name)

