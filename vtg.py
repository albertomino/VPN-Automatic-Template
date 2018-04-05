import sys
import ipaddress


class vpn:
    def __init__(self, name, key, peer, ti, remote_enc_domain, source_enc_domain, local_sources, dports, local_server, lports):
        self.name = str(name)
        self.key = str(key)
        self.peer = str(peer)
        self.ti = str(ti)
        self.remote_enc_domain = ipaddress.ip_network(remote_enc_domain)
        self.source_enc_domain = source_enc_domain
        self.local_sources = local_sources
        self.local_server = local_server
        self.dports = dports
        self.lports = lports

        #self.dnat = dict(dnat)


#PHASE-1
    def phase_1(self):
        ike = '' +\
        '\nset security ike proposal %s description \"VPN con %s\"' % (self.name, self.name) +\
        '\nset security ike proposal %s authentication-method pre-shared-keys' % self.name +\
        '\nset security ike proposal %s dh-group group2' % self.name +\
        '\nset security ike proposal %s authentication-algorithm sha1' % self.name +\
        '\nset security ike proposal %s encryption-algorithm aes-256-cbc' % self.name +\
        '\nset security ike proposal %s lifetime-seconds 86400' % self.name +\
        '\n' +\
        '\nset security ike policy %s mode main' % self.name +\
        '\nset security ike policy %s proposals %s' % (self.name, self.name) +\
        '\nset security ike policy %s pre-shared-key ascii-text %s' % (self.name, self.key)

        return ike

#PHASE-2
    def phase_2(self):
        ipsec = '' +\
        '\nset security ipsec proposal %s protocol esp' % self.name +\
        '\nset security ipsec proposal %s authentication-algorithm hmac-sha1-96' % self.name +\
        '\nset security ipsec proposal %s encryption-algorithm aes-256-cbc' % self.name +\
        '\nset security ipsec proposal %s lifetime-seconds 3600' % self.name +\
        '\n' +\
        '\nset security ipsec policy %s_IPSEC_POLICY proposals %s' % (self.name, self.name)

        return ipsec


#IKE GATEWAY

    def ike_gateway(self):
        ikegateway = '' +\
        '\nset security ike gateway %s ike-policy %s' % (self.name, self.name) +\
        '\nset security ike gateway %s address %s' % (self.name, self.peer) +\
        '\nset security ike gateway %s dead-peer-detection always-send' % self.name +\
        '\nset security ike gateway %s external-interface reth1.404' % self.name +\
        '\nset security ike gateway %s general-ikeid' % self.name

        return ikegateway


#VPN TUNEL DEFINITION
    def vpn(self):
        vpntunnel = '' +\
        '\nset security ipsec vpn %s bind-interface st0.%s' % (self.name, self.ti) +\
        '\nset security ipsec vpn %s ike gateway %s' % (self.name, self.name) +\
        '\nset security ipsec vpn %s ike ipsec-policy %s_IPSEC_POLICY' % (self.name, self.name) +\
        '\nset security ipsec vpn %s establish-tunnels immediately' % self.name

        return vpntunnel


#INTERFACE TUNEL DEFINITION
    def tunel_interface(self):
        ti = '' +\
        '\nset interfaces st0 unit %s description \"VPN %s\"' % (self.ti, self.name) +\
        '\nset interfaces st0 unit %s family inet mtu 1436' % self.ti +\
        '\nset security zones security-zone DMZ_VPN interfaces st0.%s' % self.ti

        return ti


#STATIC ROUTE
    def static_route(self):
        #static_routes = []
        #for ip in self.remote_enc_domain: static_routes.append('set routing-options static route %s next-hop st0.%s' % #(ipaddress.ip_network(ip), self.ti))
        sr = '\nset routing-options static route %s next-hop st0.%s' % (self.remote_enc_domain, self.ti)
        #for ip in static_routes: sr = sr + '\n' + ip
        return sr


#MODIFYING PREFIX-LIST TO PROCESS THE NEW VPN TRAFFIC
    def prefix_list(self):
        #epoints = []
        #for ip in self.remote_enc_domain: epoints.append('set policy-options prefix-list PBR_Inet-0 %s' % #ipaddress.ip_network(ip))
        pl = '\nset policy-options prefix-list PBR_Inet-0 %s' % self.remote_enc_domain
        #for prefixes in epoints: pl = pl + '\n' + prefixes
        return pl


#NATs

#OUTBOUND TRAFFIC FROM MELI TO REMOTE-ENDPOINTS:

    def source_pool(self):
        spools = '\nset security nat source pool SOURCE-POOL-%s_%s address %s' % (self.name, self.source_enc_domain, self.source_enc_domain)
        self.snat_pool_name = 'SOURCE-POOL-%s_%s' % (self.name, self.source_enc_domain)
        return spools

    def outbound_nat(self):
        lsources = []
        rendpoints = []
        self.dports = []
        for ip in self.local_sources: lsources.append('set security nat source rule-set NAT_SRC_VPN rule SNAT-VPN-%s match source-address %s' % (self.name, ipaddress.ip_network(ip)))
        #for ip in self.remote_enc_domain: rendpoints.append('set security nat source rule-set NAT_SRC_VPN rule SNAT-VPN-%s match #destination-address %s' % (self.name, ipaddress.ip_network(ip)))
        for port in self.dports: dports.append('set security nat source rule-set NAT_SRC_VPN rule SNAT-VPN-%s match destination-port %s' % (self.name, port))
        outbound_nat = ''
        for sources in lsources: outbound_nat = outbound_nat + '\n' + sources
        #for rendpoint in rendpoints: outbound_nat = outbound_nat + '\n' + rendpoint
        outbound_nat = outbound_nat + '\nset security nat source rule-set NAT_SRC_VPN rule SNAT-VPN-%s match destination-address %s' % (self.name, self.remote_enc_domain)
        for dport in self.dports: outbound_nat = outbound_nat + '\n' + dport
        outbound_nat = outbound_nat + '\n' + 'set security nat source rule-set NAT_SRC_VPN rule SNAT-VPN-%s then source-nat pool %s \n' % (self.name, self.snat_pool_name)
        return outbound_nat


#INBOUND TRAFFIC FROM REMOTE ENDPOINTS:

    def destination_pool(self):
        dpool = 'set security nat destination pool DNAT-POOL-%s_%s address %s' % (self.name, self.local_server, self.local_server)
        self.dnat_pool_name = 'DNAT-POOL-%s_%s' % (self.name, self.local_server)
        return dpool

    def destination_nat(self):
        lports = []
        for port in self.lports: lports.append('set security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match destination-port %s' % (self.name, port))
        destination_nat = '\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match source-address %s' % (self.name, self.remote_enc_domain) +\
        '\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match destination-address %s' % (self.name, self.source_enc_domain)
        for lp in lports: destination_nat = destination_nat + '\n' + lp
        destination_nat = destination_nat + '\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s then destination-nat pool %s' % (self.name, self.dnat_pool_name)
        return destination_nat


#SOURCE NAT FOR INBOUND TRAFFIC

    def inbound_source_pool(self):
        inbound_spools = '\nset security nat source pool SOURCE-POOL-%s_%s address %s' % (self.name, self.source_enc_domain, self.source_enc_domain)
        self.inbound_snat_pool_name = 'SOURCE-POOL-%s_%s' % (self.name, self.source_enc_domain)
        return inbound_spools

    def inbound_nat(self):
        inbound_nat = '\nset security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match source-address %s' % (self.name, self.remote_enc_domain) +\
        '\nset security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match destination-address %s' % (self.name, self.local_server)
        local_ports = []
        for port in self.lports: local_ports.append('set security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match destination-port %s' % (self.name, port))
        for sport in local_ports: inbound_nat = inbound_nat + '\n' + sport
        inbound_nat = inbound_nat + '\n' + 'set security nat source rule-set SNAT_VPN_TO_B2B rule SNAT-%s then source-nat pool %s \n' % (self.name, self.inbound_snat_pool_name)
        return inbound_nat
'''

POLICIES

Tener en cuenta el procesamiento de NATs para el armado de las policies.

OUTBOUND TRAFFIC FROM MELI

FROM DMZ_B2B TO DMZ_VPN

set security zones security-zone DMZ_B2B address-book address INSTORE-API-APP_10.X.X.0/23 10.X.X.0/23

set security zones security-zone DMZ_VPN address-book address CLIENTE-SITE-A-SERVER-TEST_172.X.X.77 172.X.X.77/32
set security zones security-zone DMZ_VPN address-book address CLIENTE-SITE-A-SERVER-PROD_172.X.X.78 172.X.X.78/32

set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match source-address
INSTORE-API-APP_10.X.X.0/23
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match source-address Batmans
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match destination-address CLIENTE-SITE-A-SERVER-TEST_172.X.X.77
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match destination-address CLIENTE-SITE-A-SERVER-PROD_172.X.X.78
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match application junos-http
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS match application junos-https
set security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_CLIENTE-SITE-A_SERVERS then permit


INBOUND TRAFFIC FROM PROVEEDOR

FROM DMZ_VPN TO DMZ_B2B

set security zones security-zone DMZ_B2B address-book address CLIENTE-VIP-APP_10.X.X.21/32 10.X.X.21/32

set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS match source-address CLIENTE-SITE-A-SERVER-TEST_172.X.X.77
set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS match source-address CLIENTE-SITE-A-SERVER-PROD_172.X.X.78
set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS match destination-address CLIENTE-VIP-APP_10.X.X.21/32
set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS match application junos-http
set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS match application junos-https
set security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_CLIENTE-SITE-A_SERVERS then permit


Pre-Shared-key
yY4bAGPGuZ67XRHz
'''

def main():
    new_vpn = vpn(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7].split(','), sys.argv[8].split(','), sys.argv[9], sys.argv[10].split(','))
    print(new_vpn.phase_1())
    print(new_vpn.phase_2())
    print(new_vpn.ike_gateway())
    print(new_vpn.vpn())
    print(new_vpn.tunel_interface())
    print(new_vpn.static_route())
    print(new_vpn.prefix_list())
    print(new_vpn.source_pool())
    print(new_vpn.outbound_nat())
    print(new_vpn.destination_pool())
    print(new_vpn.destination_nat())
    print(new_vpn.inbound_source_pool())
    print(new_vpn.inbound_nat())

if __name__ == '__main__':
    main()
