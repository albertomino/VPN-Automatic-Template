import sys
import ipaddress
import json


class vpn:
    def __init__(self, name, key, peer, ti, remote_enc_domain, source_enc_domain, local_sources, dports, local_server, lports, vpn_settings):
    #def __init__(self, settings):
        #self.vpn_settings = json.loads(vpn_settings)
        self.vpn_general = vpn_settings["vpn"]
        self.ike_proposal = vpn_settings["ike_proposal"]
        self.ike_policy = vpn_settings["ike_policy"]
        self.ike_gateway = vpn_settings["ike_gateway"]
        self.ike_gateway = vpn_settings["ike_gateway"]
        self.ipsec_proposal = vpn_settings["ipsec_proposal"]
        self.ipsec_policy = vpn_settings["ipsec_policy"]
        self.vpn_tunnel_definition = vpn_settings["vpn_tunnel_definition"]
        self.encryption_domains = vpn_settings["encryption_domains"]
        self.nat_encryption_domains = vpn_settings["nat_encryption_domains"]
        self.snat_pools = vpn_settings["snat_pools"]["pools"]
        self.ports = vpn_settings["ports"]
        self.local_server = vpn_settings["local_server"]
        #self.vpn_name = vpn_settings["vpn"]["vpn_name"]
        #self.key = vpn_settings["ike_policy"]["pre_shared_key"]
        #self.peer = vpn_settings["ike_gateway"]["address"]
        #self.si = vpn_settings["vpn_tunnel_definition"]["secure_interface"]
        #self.ike_proposal_name = vpn_settings["ike_proposal"]["name"]
        #self.ipsec_policy_name = vpn_settings["ipsec_policy"]["name"]
        #self.remote_enc_domains = vpn_settings["encryption_domains"]["remote"]
        #self.remote_enc_domain = ipaddress.ip_network(remote_enc_domain)
        #self.source_enc_domain = source_enc_domain
        #self.local_sources = local_sources
        #self.local_server = local_server
        #self.dports = dports
        #self.lports = lports


#PHASE-1
    def phase_1(self):
        ike = "" +\
        "\nset security ike proposal %s description %s" % (self.ike_proposal["name"], self.vpn_general["description"]) +\
        "\nset security ike proposal %s authentication-method %s" % (self.ike_proposal["name"], self.ike_proposal["authentication_method"]) +\
        "\nset security ike proposal %s dh-group %s" % (self.ike_proposal["name"], self.ike_proposal["diffie_hellman_group"]) +\
        "\nset security ike proposal %s authentication-algorithm %s" % (self.ike_proposal["name"], self.ike_proposal["authentication_algorithm"]) +\
        "\nset security ike proposal %s encryption-algorithm %s" % (self.ike_proposal["name"], self.ike_proposal["encryption_algorithm"]) +\
        "\nset security ike proposal %s lifetime-seconds %s" % (self.ike_proposal["name"], self.ike_proposal["lifetime"]) +\
        "\n" +\
        "\nset security ike policy %s mode main" % self.ike_policy["name"] +\
        "\nset security ike policy %s proposals %s" % (self.ike_policy["name"], self.ike_proposal["name"]) +\
        "\nset security ike policy %s pre-shared-key ascii-text %s" % (self.ike_policy["name"], self.ike_policy["pre_shared_key"])

        return ike

#PHASE-2
    def phase_2(self):
        ipsec = "" +\
        "\nset security ipsec proposal %s protocol esp" % self.ipsec_proposal["name"] +\
        "\nset security ipsec proposal %s authentication-algorithm %s" % (self.ipsec_proposal["name"], self.ipsec_proposal["authentication_algorithm"]) +\
        "\nset security ipsec proposal %s encryption-algorithm %s" % (self.ipsec_proposal["name"], self.ipsec_proposal["encryption_algorithm"]) +\
        "\nset security ipsec proposal %s lifetime-seconds %s" % (self.ipsec_proposal["name"], self.ipsec_proposal["lifetime"]) +\
        "\n" +\
        "\nset security ipsec policy %s proposals %s" % (self.ipsec_policy["name"], self.ipsec_proposal["name"])

        if self.ipsec_policy["pfs"] == True: ipsec = ipsec + "\nset security ipsec policy %s perfect-forward-secrecy keys %s" % (self.ipsec_policy["name"], self.ipsec_policy["keys"])

        return ipsec


#IKE GATEWAY

    def gateway(self):
        ikegateway = "" +\
        "\nset security ike gateway %s ike-policy %s" % (self.ike_gateway["name"], self.ike_policy["name"]) +\
        "\nset security ike gateway %s address %s" % (self.ike_gateway["name"], self.ike_gateway["address"]) +\
        "\nset security ike gateway %s external-interface %s" % (self.ike_gateway["name"], self.ike_gateway["external_interface"]) +\
        "\nset security ike gateway %s version %s" % (self.ike_gateway["name"], self.ike_gateway["version"])

        if self.ike_gateway["general-ikeid"] == True: ikegateway = ikegateway + "\nset security ike gateway %s general-ikeid" % self.ike_gateway["name"]

        return ikegateway


#VPN TUNEL DEFINITION
    def vpn(self):
        vpntunnel = "" +\
        "\nset security ipsec vpn %s bind-interface st0.%s" % (self.vpn_tunnel_definition["name"], self.vpn_tunnel_definition["secure_interface"]) +\
        "\nset security ipsec vpn %s ike gateway %s" % (self.vpn_tunnel_definition["name"], self.ike_gateway["name"]) +\
        "\nset security ipsec vpn %s ike ipsec-policy %s" % (self.vpn_tunnel_definition["name"], self.ipsec_policy["name"]) +\
        "\nset security ipsec vpn %s establish-tunnels immediately" % self.vpn_tunnel_definition["name"]

        return vpntunnel


#INTERFACE TUNEL DEFINITION
    def tunel_interface(self):
        ti = "" +\
        "\nset interfaces st0 unit %s description %s" % (self.vpn_tunnel_definition["secure_interface"], self.vpn_general["description"]) +\
        "\nset security zones security-zone DMZ_VPN interfaces st0.%s" % self.vpn_tunnel_definition["secure_interface"]

        return ti


#STATIC ROUTE
    def static_route(self):
        comando = ""
        for ip in self.encryption_domains["remote"]:
            comando = comando + "\n" + "set routing-options static route %s next-hop st0.%s" % (ip.get("net"),
            self.vpn_tunnel_definition["secure_interface"])
        return comando


#MODIFYING PREFIX-LIST TO PROCESS THE NEW VPN TRAFFIC
    def prefix_list(self):
        comando = ""
        for ip in self.encryption_domains["remote"]: comando = comando + "\n" + "set policy-options prefix-list PBR_Inet-0 %s" % ip.get("net")
        return comando


#NATs

##OUTBOUND TRAFFIC FROM MELI TO REMOTE-ENDPOINTS:

    def source_pool(self):
        snat_pools = ""
        self.snat_pools_names = {}
        for ip in self.encryption_domains["local"]:
            snat_pools = snat_pools + "\nset security nat source pool %s_%s_%s address %s" % (self.vpn_general["name"], ip.get("env"), ip.get("net"), \
            ip.get("net"))
            self.snat_pools_names[ip.get("env")] = "%s_%s_%s" % (self.vpn_general["name"], ip.get("env"), ip.get("net"))

        return snat_pools

    def outbound_nat(self):
        command = ""

        for env in self.snat_pools:
            for pool in env["nets"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match source-address %s" % \
            (self.vpn_general["name"], env["env"], pool)

        for env in self.nat_encryption_domains["remote"]:
             command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match destination-address %s" % \
             (self.vpn_general["name"], env["env"], env["net"])

        for env in self.ports["dports"]:
            command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.encryption_domains["local"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s then source-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.snat_pools_names[env["env"]])

        return command


##INBOUND TRAFIC FROM CLIENT TO MELI:

    def destination_pool(self):
        dpools = ""
        self.dnat_pool_names = {}
        for env in self.local_server:
            dpools = dpools + "\nset security nat destination pool %s_%s_%s address %s" % \
            (self.vpn_general["name"], env["env"], env["server"], env["server"])
            self.dnat_pool_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["server"])
        #"set security nat destination pool DNAT-POOL-%s_%s address %s" % (self.vpn_general["name"], self.local_server, self.local_server)
        #self.dnat_pool_name = "DNAT-POOL-%s_%s" % (self.vpn_name, self.local_server)
        return dpools

    def destination_nat(self):
        #lports = []

        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s match source-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.encryption_domains["local"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.ports["lports"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.local_server:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s then destination-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.dnat_pool_names[env["env"]])

        #for port in self.lports: lports.append("set security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match destination-port %s" % (self.vpn_name, port))
        #destination_nat = "\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match source-address %s" % (self.vpn_name, self.remote_enc_domain) +\
        #"\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s match destination-address %s" % (self.vpn_name, self.source_enc_domain)
        #for lp in lports: destination_nat = destination_nat + "\n" + lp
        #destination_nat = destination_nat + "\nset security nat destination rule-set NAT_DEST_VPN rule DNAT-VPN-%s then destination-nat pool %s" % (self.vpn_name, self.dnat_pool_name)

        return command


#SOURCE NAT FOR INBOUND TRAFFIC

    def inbound_source_pool(self):
        inbound_spools = "\nset security nat source pool SOURCE-POOL-%s_%s address %s" % (self.vpn_name, self.source_enc_domain, self.source_enc_domain)
        self.inbound_snat_pool_name = "SOURCE-POOL-%s_%s" % (self.vpn_name, self.source_enc_domain)
        return inbound_spools

    def inbound_nat(self):
        inbound_nat = "\nset security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match source-address %s" % (self.vpn_name, self.remote_enc_domain) +\
        "\nset security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match destination-address %s" % (self.vpn_name, self.local_server)
        local_ports = []
        for port in self.lports: local_ports.append("set security nat source rule-set SNAT_VPN_TO_B2B rule SNAT_%s match destination-port %s" % (self.vpn_name, port))
        for sport in local_ports: inbound_nat = inbound_nat + "\n" + sport
        inbound_nat = inbound_nat + "\n" + "set security nat source rule-set SNAT_VPN_TO_B2B rule SNAT-%s then source-nat pool %s \n" % (self.vpn_name, self.inbound_snat_pool_name)
        return inbound_nat
"""

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
"""

def main():
    try:
        input_file = open("config.json", "r").read()
        vpn_config = json.loads(input_file)
    except IOError:
        print("config.json doesn't exist")
        return

    new_vpn = vpn(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7].split(","), sys.argv[8].split(","), sys.argv[9], sys.argv[10].split(","), vpn_config)
    #print(new_vpn.phase_1())
    #print(new_vpn.phase_2())
    #print(new_vpn.gateway())
    #print(new_vpn.vpn())
    #print(new_vpn.tunel_interface())
    #print(new_vpn.static_route())
    #print(new_vpn.prefix_list())
    print(new_vpn.source_pool())
    print(new_vpn.outbound_nat())
    print(new_vpn.destination_pool())
    print(new_vpn.destination_nat())
    #print(new_vpn.inbound_source_pool())
    #print(new_vpn.inbound_nat())

if __name__ == "__main__":
    main()
