#!/usr/bin/env python

import json
import sys
import os
import urllib.request
import uuid
import re
import ipaddress
from ipaddress import IPv4Address, AddressValueError

# *********************************************************************************************************
# ************************ Office365 - Endpoint Data Parser - Python 3 ************************************
#
# N.B. THIS IS ONLY REQUIRED IF THE CUSTOMER IS USING FULL UTM FEATURES (Web filtering, AV, SSL inpection)
# AND IS RESTRICTING OUTBOUND INTERNET ACCESS.
#
# TL;DR - Ensure you have the relevant Python modules installed as per above imports.
#       - Modify all the custom variables to your environment.
#       - Run as is, no switches.
#
# https://support.office.com/en-gb/article/managing-office-365-endpoints-99cab9d4-ef59-4207-9f2b-3728eb46bf9a?ui=en-US&rs=en-GB&ad=GB#ID0EACAAA=4._Web_service
#
# Original example script from the above link (towards the end of the page), forked with Fortigate specific output and various other
# Other formats to come - Cisco - ACL's and AnyConnect, Sonicwall, PAC files ... more suggestions welcome.
#
# Microsoft publish their Office365 endpoints (IP's, FQDN's and wilcard FQDN's) via a web service providing the data in JSON and other formats.
# The current data set is published va XML (and other feeds) but these are going to be deprecated in favour of
# API access for automation purposes.
# Old data:
# https://support.office.com/en-us/article/office-365-urls-and-ip-address-ranges-8548a211-3fe7-47cb-abb1-355ea5aa88a2?ui=en-US&rs=en-US&ad=US
#
# The endpoints are then categorised into the following 3 categories, which determine how they should be treated by firewalls,
# proxies and any other traffic inspection mechanisms (SSL inspection, web filtering etc.) that could impact
# performance and function  of O365 services:
#
# Optimize - Represents over 75% of Office 365 bandwidth, connections and volume of data. Action - Bypass/whitelist - if security policy allows.
# Allow - Required for connectivity to specific Office 365 services and features. Action - Bypass/whitelist - if security policy allows.
# Default - Uses default internet path, proxy etc, no bypass, no action to take.
#
# These generated lists should be used to create dedicated firewall policies, bypassing any UTM features where possible.
# For FQDN's, these can be added to exclusion lists for web filtering and SSL inspection.
#
# Notes:
# - This script only extracts the required Optimize and Allow categories from the Worldwide instance.
# - Reports changes (additions, removals) since previous Office365 endpoint update (ONLY if run previously). Monthly updates.
# - Current exported firewall configurations - FortiOS - 5.2, 5.4, 5.6 and 6.0. Address creation, Address group, SSL exemption lists, Static URL filter exemptions.
# - IP Address lists created in different formats - IP/CIDR, IP NETMASK, IP WILDCARD.
# - Parses out specific Service Areas (yet) i.e. Exchange Online, SharePoint, Skype (includes Teams) and Common (incudes shared and Office Online services).
# - DNS RESOLUTION:
#   If you will be using the FQDN addresses on firewalls it is imperative to use the same DNS servers (forwarders) as the internal hosts are using to ensure consistency of
#   resolution between both firewall and machines.
#   Also ensure any public DNS is geographically located as close as possible i.e. ISP DNS to improve reliable connectivity to the closest Office 365 entry point and minimise latency.
# There are 3 web methods available to extract specific data from the web service:
#
# endpoints = full (latest) list of O365 endpoints - IP's, FQDN's and wildcard FQDN's.
# changes = list of changes since previous version.
# version = list latest versions.
#
# Tested on FortiOS - 5.2.13, 5.4.9, 5.6.4 and 6.0.0
#
# 5.2 - Working - Addresses, address groups, Deep SSL exemption, static URL filter lists.
# 5.4 - Working - Addresses, address groups (FQDN & Wildcard), Deep SSL exemption, static URL filter lists.
# 5.6 - Working - Addresses, address groups (FQDN & Wildcard), Deep SSL exemption, static URL filter lists.
# 6.0 - Working - Addresses, address groups (FQDN & Wildcard), Deep SSL exemption, static URL filter lists.
#
# Rob Oravec - ITLAB - roravec@itlab
#
# Modify all the custom variables below to your environment/requirements.
#
# *********************************************************************************************************
# CUSTOM VARIABLES ****************************************************************************************
# Set all custom options here.

# DIRECTORY AND FILES
# Script will create the directory if it does not exist (assuming permissions exist), just make sure the path exists.

# Where all the extracted data will be saved to
outputDir = 'C:\\tmp\\python\\O365\\Output'
fortigateDir = 'C:\\tmp\\python\\O365\\Output\\FortiGate'

filenameVersion = 'version.txt'
filenameChangesList = 'O365-CHANGES-List.txt'
filenameAllEndpointsList = 'O365-AllEndpoints-List.txt'
filenameIPCIDRList = 'O365-IP_CIDR.txt'
filenameIPNETMASKList = 'O365-IP_Netmask.txt'
filenameIPWILDCARDList = 'O365-IP_Wildcard.txt'
filenameFQDNList = 'O365-AllFQDNs.txt'
filenameWildCardFQDNList = 'O365-AllFQDNs-Wildcard.txt'
filenameFortigateAddrCFG = 'O365-FortiGate-Addr-cfg.txt'
filenameFortigateAddrGrpCFG = 'O365-FortiGate-AddrGroup-cfg.txt'
filenameFortigateURLFilterExemptCFG = 'O365-FortiGate-URLFilter-Exempt-cfg.txt'
filenameFortigateDeepSSLExemptCFG = 'O365-FortiGate-DeepSSL-Exempt-cfg.txt'
filenameCommonIPList = 'O365-Common-IPs.txt'
filenameExchangeIPList = 'O365-Exchange-IPs.txt'
filenameSharepointIPList = 'O365-SharePoint-IPs.txt'
filenameSkypeIPList = 'O365-Skype-IPs.txt'
filenameCommonFQDNList = 'O365-Common-FQDNs.txt'
filenameExchangeFQDNList = 'O365-Exchange-FQDNs.txt'
filenameSharepointFQDNList = 'O365-SharePoint-FQDNs.txt'
filenameSkypeFQDNList = 'O365-Skype-FQDNs.txt'

# Specify the FortiOS Major version that you are generating the configurations for
fortiOSVersion = '6.0'

# FORTIGATE WEB FILTER CUSTOM CONFIGURATION
# Fortigate web filter profile name
# FYI - For existing web filtering configurations, AS TO NOT OVERWRITE THEM!:
# If the web filter profile/s already have static URL filter configurations
# then you need to make some adjustments here.
# Support for multiple web profile configurations coming soon but you can modify the configuration file that is generated
# and upload that as a script in the interim.
# If its a new web filter profile be sure to configure the rest accordingly, i.e. enabling "FortiGuard category based filter"
# and whatever else is required.

webFilterProfileName = 'ALL_USERS'

# Associate the web filter profile with the URL filter table (exempton list), 10 in this example.
# To verify if and what URL filter table a web filter profile is using; to add these new exemptions to an existing URL filter table:
# show webfilter profile
#config webfilter profile
#    edit "ALL_USERS"
#        config web
#            set urlfilter-table 10
#        end
#
# Once you have verified the table ID, set it below:

urlFilterTableID = 10
urlFilterTableName = 'ALL_USERS'
urlFilterTableIDStart = 0

# FORTIGATE DEEP SSL CUSTOM CONFIGURATION
# FYI - For existing deep SSL inspection configurations you will need to check the last used ID of any existing SSL exemptions
# and set it to the last used ID as below for example(25), along with the relevant profile name.
#
# show firewall ssl-ssh-profile
#
# config firewall ssl-ssh-profile
#      edit "NEW_PYTHON_TEST"
#          config ssl-exempt
#               edit 25

deepSSLProfileName = 'NEW_PYTHON_TEST'
deepSSLExemptID = 25

# FortiOS 5.2 has a slightly different configuration, hence the below profile name. Check the firewall configuration if in doubt.
deepSSLProfileName52 = 'deep-inspection'

# CUSTOM VARIABLES END *************************************************************************************
# JSON WEB QUERIES *****************************************************************************************

def webApiGetEndpoints(methodName, instanceName, clientRequestId):
    ws = "https://endpoints.office.com"
    requestPath = ws + '/' + methodName + '/' + instanceName + '?clientRequestId=' + clientRequestId
    request = urllib.request.Request(requestPath)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())

def webApiGetAllVersions(version, instanceName):
    ws = "https://endpoints.office.com"
    requestPath = ws + '/' + version + '/' + instanceName + '?AllVersions=true' + '&ClientRequestId=' + clientRequestId
    request = urllib.request.Request(requestPath)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())

def webApiGetChanges(methodName, instanceName, verSion, clientRequestId):
    ws = "https://endpoints.office.com"
    requestPath = ws + '/' + methodName + '/' + instanceName + '/' + verSion + '?clientRequestId=' + clientRequestId
    request = urllib.request.Request(requestPath)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())

# IPv4 parse function
def is_ipv4_only(addr):
    try:
        IPv4Address(addr.split('/')[0])
        return True
    except AddressValueError:
        return False

versionCheck = (outputDir + '\\' + filenameVersion)
changesList = (outputDir + '\\' + filenameChangesList)
allEndpointsList = (outputDir + '\\' + filenameAllEndpointsList)
exportedIPCIDRList = (outputDir + '\\' + filenameIPCIDRList)
exportedIPNETMASKList = (outputDir + '\\' + filenameIPNETMASKList)
exportedIPWILDCARDList = (outputDir + '\\' + filenameIPWILDCARDList)
exportedFQDNList = (outputDir + '\\' + filenameFQDNList)
exportedWildCardFQDNList = (outputDir + '\\' + filenameWildCardFQDNList)
fortigateAddrCFG = (fortigateDir + '\\' + filenameFortigateAddrCFG)
fortigateAddrGrpCFG = (fortigateDir + '\\' + filenameFortigateAddrGrpCFG)
fortigateURLFilterExemptCFG = (fortigateDir + '\\' + filenameFortigateURLFilterExemptCFG)
fortigateDeepSSLExemptCFG = (fortigateDir + '\\' + filenameFortigateDeepSSLExemptCFG)
commonIPList = (outputDir + '\\' + filenameCommonIPList)
exchangeIPList = (outputDir + '\\' + filenameExchangeIPList)
sharepointIPList = (outputDir + '\\' + filenameSharepointIPList)
skypeIPList = (outputDir + '\\' + filenameSkypeIPList)
commonFQDNList = (outputDir + '\\' + filenameCommonFQDNList)
exchangeFQDNList = (outputDir + '\\' + filenameExchangeFQDNList)
sharepointFQDNList = (outputDir + '\\' + filenameSharepointFQDNList)
skypeFQDNList = (outputDir + '\\' + filenameSkypeFQDNList)

# CHECK FOR ENDPOINT UPDATES *******************************************************************************

clientRequestId = str(uuid.uuid4())
getVersionMethod = webApiGetAllVersions('version', 'Worldwide')
latestVersion = (getVersionMethod['versions'][0])

if os.path.exists(versionCheck):
    fLine=open(versionCheck).readline().rstrip()
    currentVer = fLine
else:
    currentVer = '0000000000'

# GET ALL ENDPOINT DATA ************************************************************************************

# If a newer version exists or there is no version file get the latest full endpoint data
# regardless if you have a previous version
if latestVersion > currentVer:
    print()
    print('************** ENDPOINT DATA VERSION CHECK **************\n')
    print('Current Version is: '+ currentVer)
    print('Latest Version is:  '+ latestVersion + '\n')
    getEndpointMethod = webApiGetEndpoints('endpoints', 'Worldwide', clientRequestId)
else:
    print('\nYou have the latest endpoint data\n')
    sys.exit()

# OPENING FILES ********************************************************************************************

if not os.path.exists(outputDir):
    os.makedirs(outputDir)

if not os.path.exists(fortigateDir):
    os.makedirs(fortigateDir)

newWCFQDNData = open(exportedWildCardFQDNList, 'w')
newFQDNData = open(exportedFQDNList, 'w')
newFortiAddrCFG = open(fortigateAddrCFG, 'w')
newFortiAddrGrpCFG = open(fortigateAddrGrpCFG, 'w')
newFortiURLFilterExemptCFG = open(fortigateURLFilterExemptCFG, 'w')
newfortigateDeepSSLExemptCFG = open(fortigateDeepSSLExemptCFG, 'w')

# FULL ENDPOINTS METHOD ************************************************************************************

# Loop through endpoint data for optimize and allow IP/URL's only and extract specific Service Areas:
# Exchange, Sharepoint, Skype (including Teams) and Common (including Office Online)
# Extracted Service Areas also include the Common Area, which is required for all of them regardless.

# IP data
flatIps = []
exchangeIPS = []
sharepointIPS = []
skypeIPS = []
commIPS = []
masterEndpointSetIDMap = {}
for endpointSet in getEndpointMethod:
    if endpointSet['category'] in ('Optimize', 'Allow'):
        ips = endpointSet['ips'] if 'ips' in endpointSet else []
        category = endpointSet['category']
        masterEndpointsetID = endpointSet['id']
        serviceA = endpointSet['serviceArea']
        masterEndpointSetIDMap.update({masterEndpointsetID:serviceA})
        ip4s = [ip for ip in ips if '.' in ip]
        tcpPorts = endpointSet['tcpPorts'] if 'tcpPorts' in endpointSet else ''
        udpPorts = endpointSet['udpPorts'] if 'udpPorts' in endpointSet else ''
        flatIps.extend([(category, ip, tcpPorts, udpPorts) for ip in ip4s])
        # Process Exchange IP's
        if endpointSet['serviceArea'] in ('Common', 'Exchange'):
            ipExchange = endpointSet['ips'] if 'ips' in endpointSet else []
            for ipExo in range(len(ipExchange)):
                if is_ipv4_only(ipExchange[ipExo]):
                    exchangeIPS.append(ipExchange[ipExo])
        # Process SharePoint IP's
        if endpointSet['serviceArea'] in ('Common', 'SharePoint'):
            ipSharepoint = endpointSet['ips'] if 'ips' in endpointSet else []
            for ipShpt in range(len(ipSharepoint)):
                if is_ipv4_only(ipSharepoint[ipShpt]):
                    sharepointIPS.append(ipSharepoint[ipShpt])
        # Process Skype/Teams IP's
        if endpointSet['serviceArea'] in ('Common', 'Skype'):
            ipSkype = endpointSet['ips'] if 'ips' in endpointSet else []
            for ips4b in range(len(ipSkype)):
                if is_ipv4_only(ipSkype[ips4b]):
                    skypeIPS.append(ipSkype[ips4b])
        # Process Common IP's
        if endpointSet['serviceArea'] in ('Common'):
            ipCommon = endpointSet['ips'] if 'ips' in endpointSet else []
            for ipcom in range(len(ipCommon)):
                if is_ipv4_only(ipCommon[ipcom]):
                    commIPS.append(ipCommon[ipcom])

# FQDN/Wildcard FQDN data
flatUrls = []
exchangeURLS = []
sharepointURLS = []
skypeURLS = []
commURLS = []
for endpointSet in getEndpointMethod:
    if endpointSet['category'] in ('Optimize', 'Allow'):
        category = endpointSet['category']
        urls = endpointSet['urls'] if 'urls' in endpointSet else []
        tcpPorts = endpointSet['tcpPorts'] if 'tcpPorts' in endpointSet else ''
        udpPorts = endpointSet['udpPorts'] if 'udpPorts' in endpointSet else ''
        flatUrls.extend([(category, url, tcpPorts, udpPorts) for url in urls])
        # Process Exchange URL's
        if endpointSet['serviceArea'] in ('Common', 'Exchange'):
            urlExchange = endpointSet['urls'] if 'urls' in endpointSet else []
            for urlEx in range(len(urlExchange)):
                exchangeURLS.append(urlExchange[urlEx])
        # Process SharePoint URL's
        if endpointSet['serviceArea'] in ('Common', 'SharePoint'):
            urlSharepoint = endpointSet['urls'] if 'urls' in endpointSet else []
            for urlSpt in range(len(urlSharepoint)):
                sharepointURLS.append(urlSharepoint[urlSpt])
        # Process Skype URL's
        if endpointSet['serviceArea'] in ('Common', 'Skype'):
            urlSkype = endpointSet['urls'] if 'urls' in endpointSet else []
            for urlS4b in range(len(urlSkype)):
                skypeURLS.append(urlSkype[urlS4b])
        # Process Common URL's
        if endpointSet['serviceArea'] in ('Common'):
            urlCommon = endpointSet['urls'] if 'urls' in endpointSet else []
            for urlCom in range(len(urlCommon)):
                commURLS.append(urlCommon[urlCom])


# CHANGES METHOD *******************************************************************************************

# Get the latest changes, since the previous exported version
if currentVer != '0000000000':
    getChangesMethod = webApiGetChanges('changes', 'Worldwide', currentVer, clientRequestId)
    newChangesList = open(changesList, 'w')
    ipAdditions = []
    urlAdditions = []
    ipRemovals = []
    urlRemovals = []
    for endpointSetChange in getChangesMethod:
        endpointsID = endpointSetChange['endpointSetId']
        if 'add' in endpointSetChange:
            additions = endpointSetChange['add']
            if 'ips' in additions:
                ipAddressAdd = additions['ips']
                for ipAdd in range(len(ipAddressAdd)):
                        if is_ipv4_only(ipAddressAdd[ipAdd]):
                            ipAdditions.append(ipAddressAdd[ipAdd])
            if 'urls' in additions:
                urlAddressAdd = additions['urls']
                for urlAdd in range(len(urlAddressAdd)):
                    urlAdditions.append(urlAddressAdd[urlAdd])
        if 'remove' in endpointSetChange:
            removals = endpointSetChange['remove']
            if 'ips' in removals:
                ipAddressRem = removals['ips']
                for ipRem in range(len(ipAddressRem)):
                        if is_ipv4_only(ipAddressRem[ipRem]):
                            ipRemovals.append(ipAddressRem[ipRem])
            if 'urls' in removals:
                urlAddressRem = removals['urls']
                for urlRem in range(len(urlAddressRem)):
                    urlRemovals.append(urlAddressRem[urlRem])
    w = list(set(ipAdditions))
    x = list(set(ipRemovals))
    y = list(set(urlAdditions))
    z = list(set(urlRemovals))
    # Search for duplicates in both additions and removals (indicates a move to another endpoint ID or Service Area).
    for i in x:
        if i in w:
            x.remove(i)
            w.remove(i)
    for j in z:
        if j in y:
            z.remove(j)
            y.remove(j)
    # Print out changes and write changes to file
    print('*************** CHANGES SINCE LAST UPDATE ***************')
    if len(w) > 0:
        print('[IP Additions]:')
        newChangesList.write('[IP Additions]:\n')
        print('\n'.join(w))
        newChangesList.write('\n'.join(w))
        newChangesList.write('\n')
        newChangesList.write('\n')
    if len(x) > 0:
        print('\n[IP Removals]:')
        newChangesList.write('[IP Removals]:\n')
        print('\n'.join(x))
        newChangesList.write('\n'.join(x))
        newChangesList.write('\n')
        newChangesList.write('\n')
    if len(y) > 0:
        print('\n[URL Additions]:')
        newChangesList.write('[URL Additions]:\n')
        print('\n'.join(y))
        newChangesList.write('\n'.join(y))
        newChangesList.write('\n')
        newChangesList.write('\n')
    if len(z) > 0:
        print('\n[URL Removals]:')
        newChangesList.write('[URL Removals]:\n')
        print('\n'.join(z))
        newChangesList.write('\n'.join(z))
        newChangesList.write('\n')
        newChangesList.write('\n')
    print()
    newChangesList.close()
    listFiles = os.listdir(outputDir)
    print('[Changes saved to]:')
    for chg in range(len(listFiles)):
        if re.search(r"CHANGES", (listFiles[chg])):
            chgname = (listFiles[chg])
            print(chgname)
    print()

# PROCESSING ADDRESSES *************************************************************************************

# Process IP's
newIPNETMASKData = open(exportedIPNETMASKList, 'w')
newIPWILDCARDData = open(exportedIPWILDCARDList, 'w')
IPV4Endpoints = sorted(set([ip for (category, ip, tcpPorts, udpPorts) in flatIps]))
counterAddr = 0
fortiIPAddrList = []
newFortiAddrCFG.write('config firewall address\n')
for ipcidr in range(len(IPV4Endpoints)):
    counterAddr = counterAddr + 1
    # Fortigate addresses
    newFortiAddrCFG.write('edit zzzO365-' + str(counterAddr) + '\n')
    newFortiAddrCFG.write('set type ipmask\n')
    newFortiAddrCFG.write('set subnet ' + (IPV4Endpoints[ipcidr]) + '\n')
    newFortiAddrCFG.write('next\n')
    fortiIPAddrList.append('zzzO365-' + str(counterAddr))
    # IP formats
    cidrIPNet = ipaddress.ip_network(IPV4Endpoints[ipcidr])[0]
    cidrNetmask = ipaddress.ip_network(IPV4Endpoints[ipcidr])
    # Export IP NETMASK - 192.168.1.0 255.255.255.0
    newIPNETMASKData.write((str([cidrIPNet][0]) + ' ' + str(cidrNetmask.netmask) + '\n'))
    # Export IP WILDCARD MASK - 192.168.1.0 0.0.0.255
    newIPWILDCARDData.write((str([cidrIPNet][0]) + ' ' + str(cidrNetmask.hostmask) + '\n'))
if fortiOSVersion == '6.0':
    newFortiAddrCFG.write('end\n')
# End processing IP's

# Export Common IP's
newCommonIPData = open(commonIPList, 'w')
newCommonIPData.write('\n'.join(commIPS))
newCommonIPData.close()

# Export Exchange IP's
newExchangeIPData = open(exchangeIPList, 'w')
newExchangeIPData.write('\n'.join(exchangeIPS))
newExchangeIPData.close()

# Export SharePoint IP's
newSharepointIPData = open(sharepointIPList, 'w')
newSharepointIPData.write('\n'.join(sharepointIPS))
newSharepointIPData.close()

# Export Skype IP's
newSkypeIPData = open(skypeIPList, 'w')
newSkypeIPData.write('\n'.join(skypeIPS))
newSkypeIPData.close()

# Export Common FQDNs
newCommonFQDNData = open(commonFQDNList, 'w')
newCommonFQDNData.write('\n'.join(commURLS))
newCommonFQDNData.close()

# Export Exchange FQDNs
newExchangeFQDNData = open(exchangeFQDNList, 'w')
newExchangeFQDNData.write('\n'.join(exchangeURLS))
newExchangeFQDNData.close()

# Export SharePoint FQDNs
newSharepointFQDNData = open(sharepointFQDNList, 'w')
newSharepointFQDNData.write('\n'.join(sharepointURLS))
newSharepointFQDNData.close()

# Export Skype FQDNs
newSkypeFQDNData = open(skypeFQDNList, 'w')
newSkypeFQDNData.write('\n'.join(skypeURLS))
newSkypeFQDNData.close()

# Write latest version
versionData = open(versionCheck, 'w')
versionData.write(latestVersion + '\n')

# Export IP/CIDR to full endpoint list
newEnpointData = open(allEndpointsList, 'w')
newEnpointData.write('\n'.join(IPV4Endpoints))
newEnpointData.write('\n')

# Export IP/CIDR - 192.168.1.0/24
newIPCIDRData = open(exportedIPCIDRList, 'w')
newIPCIDRData.write('\n'.join(IPV4Endpoints))

# FortiGate - FQDN processing
fortiFQDNAddrList = []
fortiWCFQDNAddrList = []
counterFQDN = 0
counterWCFQDN = 0

# FortiGate - Process FQDN's/wildcard FQDN's & Static URL filter exemptions
newFortiURLFilterExemptCFG.write('config webfilter urlfilter\n')
newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableID) + '\n')
newFortiURLFilterExemptCFG.write('set name ' + urlFilterTableName + '\n')
newFortiURLFilterExemptCFG.write('config entries\n')

# FortiGate - New feature i 6.0.x
if fortiOSVersion == '6.0':
    newFortiAddrCFG.write('config firewall wildcard-fqdn custom\n')

if fortiOSVersion == '5.2':
    unsortedFQDNEndpoints = sorted(set([url for (category, url, tcpPorts, udpPorts) in flatUrls]))
    for fqdn in range(len(unsortedFQDNEndpoints)):
        str(unsortedFQDNEndpoints[fqdn])
        urlFilterTableIDStart = urlFilterTableIDStart + 1
        if re.search(r"[*]", (unsortedFQDNEndpoints[fqdn])):
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newWCFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterWCFQDN = counterWCFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type wildcard\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-WCFQDN-' + str(counterWCFQDN) + '\n')
            newFortiAddrCFG.write('set type fqdn\n')
            newFortiAddrCFG.write('set fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiWCFQDNAddrList.append('zzzO365-WCFQDN-' + str(counterWCFQDN))
        else:
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterFQDN = counterFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type simple\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-FQDN-' + str(counterFQDN) + '\n')
            newFortiAddrCFG.write('set type fqdn\n')
            newFortiAddrCFG.write('set fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiFQDNAddrList.append('zzzO365-FQDN-' + str(counterFQDN))

if fortiOSVersion == '5.4':
    unsortedFQDNEndpoints = sorted(set([url for (category, url, tcpPorts, udpPorts) in flatUrls]))
    for fqdn in range(len(unsortedFQDNEndpoints)):
        str(unsortedFQDNEndpoints[fqdn])
        urlFilterTableIDStart = urlFilterTableIDStart + 1
        if re.search(r"[*]", (unsortedFQDNEndpoints[fqdn])):
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newWCFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterWCFQDN = counterWCFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type wildcard\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-WCFQDN-' + str(counterWCFQDN) + '\n')
            newFortiAddrCFG.write('set type wildcard-fqdn\n')
            newFortiAddrCFG.write('set wildcard-fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiWCFQDNAddrList.append('zzzO365-WCFQDN-' + str(counterWCFQDN))
        else:
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterFQDN = counterFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type simple\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-FQDN-' + str(counterFQDN) + '\n')
            newFortiAddrCFG.write('set type fqdn\n')
            newFortiAddrCFG.write('set fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiFQDNAddrList.append('zzzO365-FQDN-' + str(counterFQDN))

if fortiOSVersion == '5.6':
    unsortedFQDNEndpoints = sorted(set([url for (category, url, tcpPorts, udpPorts) in flatUrls]))
    for fqdn in range(len(unsortedFQDNEndpoints)):
        str(unsortedFQDNEndpoints[fqdn])
        urlFilterTableIDStart = urlFilterTableIDStart + 1
        if re.search(r"[*]", (unsortedFQDNEndpoints[fqdn])):
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newWCFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterWCFQDN = counterWCFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type wildcard\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-WCFQDN-' + str(counterWCFQDN) + '\n')
            newFortiAddrCFG.write('set type wildcard-fqdn\n')
            newFortiAddrCFG.write('set wildcard-fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiWCFQDNAddrList.append('zzzO365-WCFQDN-' + str(counterWCFQDN))
        else:
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterFQDN = counterFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type simple\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-FQDN-' + str(counterFQDN) + '\n')
            newFortiAddrCFG.write('set type fqdn\n')
            newFortiAddrCFG.write('set fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiFQDNAddrList.append('zzzO365-FQDN-' + str(counterFQDN))

if fortiOSVersion == '6.0':
    sortedFQDN = []
    unsortedFQDNEndpoints = sorted(set([url for (category, url, tcpPorts, udpPorts) in flatUrls]))
    for fqdn in range(len(unsortedFQDNEndpoints)):
        str(unsortedFQDNEndpoints[fqdn])
        urlFilterTableIDStart = urlFilterTableIDStart + 1
        if re.search(r"[*]", (unsortedFQDNEndpoints[fqdn])):
            newEnpointData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            newWCFQDNData.write((unsortedFQDNEndpoints[fqdn]) + '\n')
            counterWCFQDN = counterWCFQDN + 1
            newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
            newFortiURLFilterExemptCFG.write('set type wildcard\n')
            newFortiURLFilterExemptCFG.write('set action exempt\n')
            newFortiURLFilterExemptCFG.write('set url ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiURLFilterExemptCFG.write('next\n')
            newFortiAddrCFG.write('edit zzzO365-WCFQDN-' + str(counterWCFQDN) + '\n')
            newFortiAddrCFG.write('set wildcard-fqdn ' + (unsortedFQDNEndpoints[fqdn]) + '\n')
            newFortiAddrCFG.write('next\n')
            fortiWCFQDNAddrList.append('zzzO365-WCFQDN-' + str(counterWCFQDN))
        else:
            sortedFQDN.append(unsortedFQDNEndpoints[fqdn])

if fortiOSVersion == '6.0':
    newFortiAddrCFG.write('end\n')

if fortiOSVersion == '6.0':
    newFortiAddrCFG.write('config firewall address\n')
    for sfqdn in range(len(sortedFQDN)):
        str(sortedFQDN[sfqdn])
        urlFilterTableIDStart = urlFilterTableIDStart + 1
        newEnpointData.write((sortedFQDN[sfqdn]) + '\n')
        newFQDNData.write((sortedFQDN[sfqdn]) + '\n')
        counterFQDN = counterFQDN + 1
        newFortiURLFilterExemptCFG.write('edit ' + str(urlFilterTableIDStart) + '\n')
        newFortiURLFilterExemptCFG.write('set type simple\n')
        newFortiURLFilterExemptCFG.write('set action exempt\n')
        newFortiURLFilterExemptCFG.write('set url ' + (sortedFQDN[sfqdn]) + '\n')
        newFortiURLFilterExemptCFG.write('next\n')
        newFortiAddrCFG.write('edit zzzO365-FQDN-' + str(counterFQDN) + '\n')
        newFortiAddrCFG.write('set type fqdn\n')
        newFortiAddrCFG.write('set fqdn ' + (sortedFQDN[sfqdn]) + '\n')
        newFortiAddrCFG.write('next\n')
        fortiFQDNAddrList.append('zzzO365-FQDN-' + str(counterFQDN))
newFortiAddrCFG.write('end\n')

newFortiURLFilterExemptCFG.write('end\n')
newFortiURLFilterExemptCFG.write('end\n')
newFortiURLFilterExemptCFG.write('config webfilter profile\n')
newFortiURLFilterExemptCFG.write('edit ' + webFilterProfileName + '\n')
newFortiURLFilterExemptCFG.write('config web\n')
newFortiURLFilterExemptCFG.write('set urlfilter-table ' + str(urlFilterTableID) + '\n')

# PROCESSING ADDRESS GROUPS ********************************************************************************

# FortiGate - IP Groups
newFortiAddrGrpCFG.write('config firewall addrgrp\n')
splitIPList = [fortiIPAddrList[x:x+200] for x in range(0, len(fortiIPAddrList), 200)]
ipGroupTotal = (len(splitIPList))
ipGroupCounter = 0
ipGroupList = []
while ipGroupCounter < ipGroupTotal:
    ipGroupCounter = ipGroupCounter + 1
    ipGroupList.append('O365-IP-Group' + (str(ipGroupCounter)))

for gID, splitIP in zip(ipGroupList, splitIPList):
    newFortiAddrGrpCFG.write('edit ' + gID + '\n')
    newFortiAddrGrpCFG.write('set member ' + (' '.join(map(str, splitIP))) + '\n')
    newFortiAddrGrpCFG.write('next\n')

# FortiGate - Wildcard FQDN Groups
if fortiOSVersion == '6.0':
    newFortiAddrGrpCFG.write('end\n')
    newFortiAddrGrpCFG.write('config firewall wildcard-fqdn group\n')
    splitWCFQDNList = [fortiWCFQDNAddrList[x:x+200] for x in range(0, len(fortiWCFQDNAddrList), 200)]
    wcFQDNGroupTotal = (len(splitWCFQDNList))
    wcFQDNGroupCounter = 0
    wcFQDNGroupList = []
    deepSSLGroupList = []
    while wcFQDNGroupCounter < wcFQDNGroupTotal:
        wcFQDNGroupCounter = wcFQDNGroupCounter + 1
        wcFQDNGroupList.append('O365-WC-FQDN-Group' + (str(wcFQDNGroupCounter)))
        deepSSLGroupList.append('O365-WC-FQDN-Group' + (str(wcFQDNGroupCounter)))
    for wcgID, splitWC in zip(wcFQDNGroupList, splitWCFQDNList):
        newFortiAddrGrpCFG.write('edit ' + wcgID + '\n')
        newFortiAddrGrpCFG.write('set member ' + (' '.join(map(str, splitWC))) + '\n')
        newFortiAddrGrpCFG.write('next\n')
        newFortiAddrGrpCFG.write('end\n')
else:
    splitWCFQDNList = [fortiWCFQDNAddrList[x:x+200] for x in range(0, len(fortiWCFQDNAddrList), 200)]
    wcFQDNGroupTotal = (len(splitWCFQDNList))
    wcFQDNGroupCounter = 0
    wcFQDNGroupList = []
    deepSSLGroupList = []
    while wcFQDNGroupCounter < wcFQDNGroupTotal:
        wcFQDNGroupCounter = wcFQDNGroupCounter + 1
        wcFQDNGroupList.append('O365-WC-FQDN-Group' + (str(wcFQDNGroupCounter)))
        deepSSLGroupList.append('O365-WC-FQDN-Group' + (str(wcFQDNGroupCounter)))
    for wcgID, splitWC in zip(wcFQDNGroupList, splitWCFQDNList):
        newFortiAddrGrpCFG.write('edit ' + wcgID + '\n')
        newFortiAddrGrpCFG.write('set member ' + (' '.join(map(str, splitWC))) + '\n')
        newFortiAddrGrpCFG.write('next\n')

# FortiGate - FQDN groups
if fortiOSVersion == '6.0':
    newFortiAddrGrpCFG.write('config firewall addrgrp\n')

splitFQDNList = [fortiFQDNAddrList[x:x+200] for x in range(0, len(fortiFQDNAddrList), 200)]
FQDNGroupTotal = (len(splitFQDNList))
FQDNGroupCounter = 0
FQDNGroupList = []
while FQDNGroupCounter < FQDNGroupTotal:
    FQDNGroupCounter = FQDNGroupCounter + 1
    FQDNGroupList.append('O365-FQDN-Group' + (str(FQDNGroupCounter)))
    deepSSLGroupList.append('O365-FQDN-Group' + (str(FQDNGroupCounter)))

for fqdngID, splitFQDN in zip(FQDNGroupList, splitFQDNList):
    newFortiAddrGrpCFG.write('edit ' + fqdngID + '\n')
    newFortiAddrGrpCFG.write('set member ' + (' '.join(map(str, splitFQDN))) + '\n')
    newFortiAddrGrpCFG.write('next\n')
    newFortiAddrGrpCFG.write('end\n')

# FORTIGATE - DEEP SSL INSPECTION EXEMPTIONS ***************************************************************

if fortiOSVersion == '5.2':
    newfortigateDeepSSLExemptCFG.write('config firewall ssl-ssh-profile\n')
    newfortigateDeepSSLExemptCFG.write('edit ' + deepSSLProfileName52 + '\n')
    newfortigateDeepSSLExemptCFG.write('config ssl-exempt\n')
    for deepSSLGroup in range(len(deepSSLGroupList)):
        deepSSLExemptID = deepSSLExemptID + 1
        groupName = (deepSSLGroupList[deepSSLGroup])
        newfortigateDeepSSLExemptCFG.write('edit ' + str(deepSSLExemptID) + '\n')
        newfortigateDeepSSLExemptCFG.write('set type address\n')
        newfortigateDeepSSLExemptCFG.write('set address ' + groupName + '\n')
        newfortigateDeepSSLExemptCFG.write('next\n')
elif fortiOSVersion == '5.4':
    newfortigateDeepSSLExemptCFG.write('config firewall ssl-ssh-profile\n')
    newfortigateDeepSSLExemptCFG.write('edit ' + deepSSLProfileName + '\n')
    newfortigateDeepSSLExemptCFG.write('config ssl-exempt\n')
    for deepSSLGroup in range(len(deepSSLGroupList)):
        deepSSLExemptID = deepSSLExemptID + 1
        groupName = (deepSSLGroupList[deepSSLGroup])
elif fortiOSVersion == '5.6':
    newfortigateDeepSSLExemptCFG.write('config firewall ssl-ssh-profile\n')
    newfortigateDeepSSLExemptCFG.write('edit ' + deepSSLProfileName + '\n')
    newfortigateDeepSSLExemptCFG.write('config ssl-exempt\n')
    for deepSSLGroup in range(len(deepSSLGroupList)):
        deepSSLExemptID = deepSSLExemptID + 1
        groupName = (deepSSLGroupList[deepSSLGroup])
elif fortiOSVersion == '6.0':
    newfortigateDeepSSLExemptCFG.write('config firewall ssl-ssh-profile\n')
    newfortigateDeepSSLExemptCFG.write('edit ' + deepSSLProfileName + '\n')
    newfortigateDeepSSLExemptCFG.write('config ssl-exempt\n')
    for deepSSLGroup in range(len(deepSSLGroupList)):
        if re.search(r"[WC]", (deepSSLGroupList[deepSSLGroup])):
            deepSSLExemptID = deepSSLExemptID + 1
            groupName = (deepSSLGroupList[deepSSLGroup])
            newfortigateDeepSSLExemptCFG.write('edit ' + str(deepSSLExemptID) + '\n')
            newfortigateDeepSSLExemptCFG.write('set type wildcard-fqdn\n')
            newfortigateDeepSSLExemptCFG.write('set wildcard-fqdn ' + groupName + '\n')
            newfortigateDeepSSLExemptCFG.write('next\n')
        else:
             deepSSLExemptID = deepSSLExemptID + 1
             groupName = (deepSSLGroupList[deepSSLGroup])
             newfortigateDeepSSLExemptCFG.write('edit ' + str(deepSSLExemptID) + '\n')
             newfortigateDeepSSLExemptCFG.write('set type address\n')
             newfortigateDeepSSLExemptCFG.write('set address ' + groupName + '\n')
             newfortigateDeepSSLExemptCFG.write('next\n')


# CLOSING FILES ********************************************************************************************
listFiles = os.listdir(outputDir)
listFgtCfgFiles = os.listdir(fortigateDir)
versionData.close()
newWCFQDNData.close()
newFQDNData.close()
newIPCIDRData.close()
newIPNETMASKData.close()
newIPWILDCARDData.close()
newEnpointData.close()
newFortiAddrCFG.close()
newFortiAddrGrpCFG.close()
newFortiURLFilterExemptCFG.write('end\n')
newFortiURLFilterExemptCFG.close()
newfortigateDeepSSLExemptCFG.write('end\n')
newfortigateDeepSSLExemptCFG.close()

print('************** FULL ENDPOINT DATA EXPORTED**************')

print('\nOffice365 Worldwide instance endpoint data downloaded... ')

print('\n[Full List]:')
for fll in range(len(listFiles)):
    if re.search(r"All", (listFiles[fll])):
        fllname = (listFiles[fll])
        print(fllname)

print('\n[Common Endpoints]:')
for com in range(len(listFiles)):
    if re.search(r"Common", (listFiles[com])):
        comname = (listFiles[com])
        print(comname)

print('\n[Exchange Endpoints]:')
for exc in range(len(listFiles)):
    if re.search(r"Exchange", (listFiles[exc])):
        excname = (listFiles[exc])
        print(excname)

print('\n[SharePoint Endpoints]:')
for spt in range(len(listFiles)):
    if re.search(r"SharePoint", (listFiles[spt])):
        sptname = (listFiles[spt])
        print(sptname)

print('\n[Skype Endpoints]:')
for s4b in range(len(listFiles)):
    if re.search(r"Skype", (listFiles[s4b])):
        s4bname = (listFiles[s4b])
        print(s4bname)

print('\n[IP Formats]:')
for ipf in range(len(listFiles)):
    if re.search(r"IP_", (listFiles[ipf])):
        ipfname = (listFiles[ipf])
        print(ipfname)
print()

if fortiOSVersion == '5.2':
    #print('\nOffice365 endpoint data downloaded ... ')
    print('[Configuration files for FortiOS ' + fortiOSVersion + '.X generated]:')
elif fortiOSVersion == '5.4':
    #print('\nOffice365 endpoint data downloaded ... ')
    print('[Configuration files for FortiOS ' + fortiOSVersion + '.X generated]:')
elif fortiOSVersion == '5.6':
    #print('\nOffice365 endpoint data downloaded ... ')
    print('[Configuration files for FortiOS ' + fortiOSVersion + '.X generated]:')
elif fortiOSVersion == '6.0':
    #print('\nOffice365 endpoint data downloaded ... ')
    print('[Configuration files for FortiOS ' + fortiOSVersion + '.X generated]:')

# FILE LIST
for fgtcfg in range(len(listFgtCfgFiles)):
    if re.search(r"FortiGate", (listFgtCfgFiles[fgtcfg])):
        fgtcfgname = (listFgtCfgFiles[fgtcfg])
        print(fgtcfgname)


print()
