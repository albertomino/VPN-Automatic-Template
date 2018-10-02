#import sys
#import ipaddress
import json


class vpn:
    def __init__(self, settings):
        self.vpn_general = settings["vpn"]
        self.ike_proposal = settings["ike_proposal"]
        self.ike_policy = settings["ike_policy"]
        self.ike_gateway = settings["ike_gateway"]
        self.ike_gateway = settings["ike_gateway"]
        self.ipsec_proposal = settings["ipsec_proposal"]
        self.ipsec_policy = settings["ipsec_policy"]
        self.vpn_tunnel_definition = settings["vpn_tunnel_definition"]
        self.encryption_domains = settings["encryption_domains"]
        self.nat_encryption_domains = settings["nat_encryption_domains"]
        self.snat_pools = settings["snat_pools"]["pools"]
        self.ports = settings["ports"]
        self.local_server = settings["local_server"]


#PHASE-1
    def phase_1(self):
        ike = "" +\
        "\nset security ike proposal %s description \"%s\"" % (self.ike_proposal["name"], self.vpn_general["description"]) +\
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
        "\nset interfaces st0 unit %s description \"%s\"" % (self.vpn_tunnel_definition["secure_interface"], self.vpn_general["description"]) +\
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

    def outbound_dnat_pool(self):
        command = ""

        self.outbound_dnat_pool_names = {}

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security nat destination pool %s_%s_%s address %s" % \
            (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0],env["net"])
            self.outbound_dnat_pool_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0])

        return command


    def outbound_dnat(self):
        command = ""

        for env in self.snat_pools:
            for pool in env["nets"]:
                command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s_OUT-DNAT match source-address %s" % \
                (self.vpn_general["name"], env["env"], pool)

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s_OUT-DNAT match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s_OUT-DNAT then destination-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.outbound_dnat_pool_names[env["env"]])

        return command


    def source_pool(self):
        snat_pools = ""

        self.snat_pools_names = {}

        for ip in self.nat_encryption_domains["local"]:
            snat_pools = snat_pools + "\nset security nat source pool %s_%s_%s address %s" % (self.vpn_general["name"], ip.get("env"), ip.get("net").replace(".", "_").split("/")[0], \
            ip.get("net"))
            self.snat_pools_names[ip.get("env")] = "%s_%s_%s" % (self.vpn_general["name"], ip.get("env"), ip.get("net").replace(".", "_").split("/")[0])

        return snat_pools

    def outbound_nat(self):
        command = ""

        for env in self.snat_pools:
            for pool in env["nets"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s_OUT-SNAT match source-address %s" % \
            (self.vpn_general["name"], env["env"], pool)

        for env in self.encryption_domains["remote"]:
             command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s_OUT-SNAT match destination-address %s" % \
             (self.vpn_general["name"], env["env"], env["net"])

        for env in self.ports["dports"]:
            command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s_OUT-SNAT match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.encryption_domains["local"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s_OUT-SNAT then source-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.snat_pools_names[env["env"]])

        return command


##INBOUND TRAFIC FROM CLIENT TO MELI:

    def destination_pool(self):
        dpools = ""

        self.dnat_pool_names = {}

        for env in self.local_server:
            dpools = dpools + "\nset security nat destination pool %s_%s_%s address %s" % \
            (self.vpn_general["name"], env["env"], env["server"].replace(".", "_").split("/")[0], env["server"])
            self.dnat_pool_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["server"].replace(".", "_").split("/")[0])

        return dpools

    def destination_nat(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s_IN-DNAT match source-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.encryption_domains["local"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s_IN-DNAT match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.ports["lports"]:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s_IN-DNAT match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.local_server:
            command = command + "\nset security nat destination rule-set NAT_DEST_VPN rule %s_%s_IN-DNAT then destination-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.dnat_pool_names[env["env"]])

        return command


##SOURCE NAT FOR INBOUND TRAFFIC

    def inbound_source_pool(self):
        inbound_spools = ""

        self.inbound_spools_names = {}

        for env in self.nat_encryption_domains["remote"]:
            inbound_spools = inbound_spools + "\nset security nat source pool %s_%s_%s address %s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0], env["net"])
            self.inbound_spools_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0])

        return inbound_spools

    def inbound_nat(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s_IN-SNAT match source-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.local_server:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s_IN-SNAT match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["server"])

        for env in self.ports["lports"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s_IN-SNAT match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s_IN-SNAT then source-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.inbound_spools_names[env["env"]])

        return command


##POLICIES


class policy:
    def __init__(self, settings):
        self.vpn_general = settings["vpn"]
        self.encryption_domains = settings["encryption_domains"]
        self.nat_encryption_domains = settings["nat_encryption_domains"]
        self.snat_pools = settings["snat_pools"]["pools"]
        self.ports = settings["ports"]
        self.local_server = settings["local_server"]

    def applications(self):
        command = ""

        self.applications_names_local = {}

        self.applications_names_remote = {}

        for app in self.ports["lports"]:
            command = command + "\nset applications application %s-%s-RPORT-TCP-%s protocol tcp" % (self.vpn_general["name"], app["name"], app["port"])
            command = command + "\nset applications application %s-%s-RPORT-TCP-%s destination-port %s" % (self.vpn_general["name"], app["name"], app["port"], app["port"])
            self.applications_names_local[app["env"]] = "%s-%s-RPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])


        for app in self.ports["dports"]:
            command = command + "\nset applications application %s-%s-LPORT-TCP-%s protocol tcp" % (self.vpn_general["name"], app["name"], app["port"])
            command = command + "\nset applications application %s-%s-LPORT-TCP-%s destination-port %s" % (self.vpn_general["name"], app["name"], app["port"], app["port"])
            self.applications_names_remote[app["env"]] = "%s-%s-LPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])

        return command

    def address_book(self):
        command = ""

        self.address_book_dmz_b2b = []

        self.address_book_dmz_b2b_server = {}

        self.address_book_dmz_vpn = {}

        for env in self.snat_pools:
            for source in env["nets"]:
                command = command + "\nset security zones security-zone DMZ_B2B address-book address %s_%s_%s %s" % \
                (env["name"], env["env"], source, source)
                self.address_book_dmz_b2b.append({env["env"] : "%s_%s_%s" % (env["name"], env["env"], source)})

        for env in self.local_server:
            command = command + "\nset security zones security-zone DMZ_B2B address-book address %s_%s_%s %s" % \
            (env["name"], env["env"], env["server"], env["server"])
            self.address_book_dmz_b2b_server[env["env"]] = "%s_%s_%s" % (env["name"], env["env"], env["server"])

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security zones security-zone DMZ_VPN address-book address %s_%s_%s %s" % \
            (self.vpn_general["name"], env["env"], env["net"], env["net"])
            self.address_book_dmz_vpn[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"])

        return command

##OUTBOUND TRAFFIC FROM MELI, FROM DMZ_B2B TO DMZ_VPN.

    def outbound(self):
        command = ""

        for env in self.address_book_dmz_b2b:
            for k, v in env.items():
                command = command + "\nset security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS match source-address %s" % \
                (self.vpn_general["name"], k, v)

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS match destination-address %s" % \
            (self.vpn_general["name"], env["env"], self.address_book_dmz_vpn[env["env"]])

        for env in self.ports["dports"]:
            command = command + "\nset security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS match application %s" % \
            (self.vpn_general["name"], env["env"], self.applications_names_remote[env["env"]])

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS then permit" % \
            (self.vpn_general["name"], env["env"])

        return command

##INBOUND TRAFFIC FROM PROVEEDOR, FROM DMZ_VPN TO DMZ_B2B.

    def inbound(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s match source-address %s" % \
            (self.vpn_general["name"], env["env"], self.address_book_dmz_vpn[env["env"]])

        for env, dst in self.address_book_dmz_b2b_server.items():
            command = command + "\nset security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s match destination-address %s" % \
            (self.vpn_general["name"], env, dst)

        for env in self.ports["lports"]:
            command = command + "\nset security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s match application %s" % \
            (self.vpn_general["name"], env["env"], self.applications_names_local[env["env"]])

        for env in self.local_server:
            command = command + "\nset security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s then permit" % (self.vpn_general["name"], env["env"])

        return command


def main():
    try:
        input_file = open("config.json", "r").read()
        settings = json.loads(input_file)
    except IOError:
        print("config.json doesn't exist")
        return

    new_vpn = vpn(settings)
    new_policy = policy(settings)
    print(new_vpn.phase_1())
    print(new_vpn.phase_2())
    print(new_vpn.gateway())
    print(new_vpn.vpn())
    print(new_vpn.tunel_interface())
    print(new_vpn.static_route())
    print(new_vpn.prefix_list())
    print(new_vpn.outbound_dnat_pool())
    print(new_vpn.outbound_dnat())
    print(new_vpn.source_pool())
    print(new_vpn.outbound_nat())
    print(new_vpn.destination_pool())
    print(new_vpn.destination_nat())
    print(new_vpn.inbound_source_pool())
    print(new_vpn.inbound_nat())
    print(new_policy.applications())
    print(new_policy.address_book())
    print(new_policy.outbound())
    print(new_policy.inbound())

if __name__ == "__main__":
    main()
