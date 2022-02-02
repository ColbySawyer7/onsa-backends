"""
OpenNSA backend for OVS switching.

Author: Colby Sawyer
Date: 2-22-2022
"""

import random

from twisted.python import log
from twisted.internet import defer

#TODO this should be resolved
from opennsa import config
from opennsa import constants as cnt
from opennsa.backends.common import genericbackend, ssh

#TODO Update these parameters to OVS specifics

# parameterized commands for layer 2 (NOT IN USE)
COMMAND_CONFIG                  = 'equipmentgrp set shelf 1 group 7' # Equipment group that is configured
COMMAND_SAVE_CONFIG             = 'configuration save'

COMMAND_PORT_DESCRIPTION        = 'port set port %(port)s description %(desc)s' #Set description for a physical port
COMMAND_VSWITCH_CREATE          = 'virtual-switch create vs %(switch)s' #Create virtual switch with a name
COMMAND_SUBPORT_CREATE          = 'sub-port create sub-port %(name)s parent-port %(port)s classifier-precedence %(id)s' #Create virtual interface on a physical port
COMMAND_SUBPORT_ADD_VLAN        = 'sub-port add sub-port %(name)s class-element %(uid)s vtag-stack %(vlan)s' #Create vlan interface on named virtual interface
COMMAND_SUBPORT_CONFIGURE_VLAN  = 'sub-port set sub-port %(name)s ingress-l2-transform push-8100.%(vlan)s.0 egress-l2-transform pop' # Push vlan tag on receiving, pop when sending
COMMAND_ATTACH_SUBPORT          = 'virtual-switch interface attach sub-port %(name)s vs %(switch)s' #Attach virtual interface to virtual switch

#TODO Remove TL1 usage
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
LOG_SYSTEM = 'OVS'
