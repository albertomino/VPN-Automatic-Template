import json
import click

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
        "\nset security ike proposal %s authentication-method %s" % (self.ike_proposal["name"],self.ike_proposal["authentication_method"]) +\
        "\nset security ike proposal %s dh-group %s" % (self.ike_proposal["name"], self.ike_proposal["diffie_hellman_group"])+\
        "\nset security ike proposal %s authentication-algorithm %s" % (self.ike_proposal["name"],self.ike_proposal["authentication_algorithm"]) +\
        "\nset security ike proposal %s encryption-algorithm %s" % (self.ike_proposal["name"],self.ike_proposal["encryption_algorithm"]) +\
        "\nset security ike proposal %s lifetime-seconds %s" % (self.ike_proposal["name"], self.ike_proposal["lifetime"]) +\
        "\n" +\
        "\nset security ike policy %s mode main" % self.ike_policy["name"] +\
        "\nset security ike policy %s proposals %s" % (self.ike_policy["name"], self.ike_proposal["name"]) +\
        "\nset security ike policy %s pre-shared-key ascii-text %s" % (self.ike_policy["name"],self.ike_policy["pre_shared_key"])

        return ike

    def phase_1_delete(self):
        ike = "" +\
        "\ndetete security ike proposal %s" % self.ike_proposal["name"] +\
        "\ndelete security ike policy %s" % self.ike_policy["name"]

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

    def phase_2_delete(self):
        ipsec = "" +\
        "\ndelete security ipsec proposal %s" % self.ipsec_proposal["name"] +\
        "\ndelete security ipsec policy %s" % self.ipsec_policy["name"]

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

    def gateway_delete(self):
        ikegateway = "" +\
        "\ndelete security ike gateway %s" % self.ike_gateway["name"]

        return ikegateway

#VPN TUNEL DEFINITION
    def vpn(self):
        vpntunnel = "" +\
        "\nset security ipsec vpn %s bind-interface st0.%s" % (self.vpn_tunnel_definition["name"], self.vpn_tunnel_definition["secure_interface"]) +\
        "\nset security ipsec vpn %s ike gateway %s" % (self.vpn_tunnel_definition["name"], self.ike_gateway["name"]) +\
        "\nset security ipsec vpn %s ike ipsec-policy %s" % (self.vpn_tunnel_definition["name"], self.ipsec_policy["name"]) +\
        "\nset security ipsec vpn %s establish-tunnels immediately" % self.vpn_tunnel_definition["name"]

        if self.vpn_tunnel_definition["traffic-selector"] == True:
            for local in self.encryption_domains["local"]:
                vpntunnel = vpntunnel + "\nset security ipsec vpn %s traffic-selector %s local-ip %s" % (self.vpn_tunnel_definition["name"], local["env"] , local["net"])
            for remote in self.encryption_domains["remote"]:
                vpntunnel = vpntunnel + "\nset security ipsec vpn %s traffic-selector %s remote-ip %s" % (self.vpn_tunnel_definition["name"], remote["env"] , remote["net"])

        return vpntunnel

    def vpn_delete(self):
        vpntunnel = "" +\
        "\ndelete security ipsec vpn %s" % self.vpn_tunnel_definition["name"]

        return vpntunnel

#INTERFACE TUNEL DEFINITION
    def tunel_interface(self):
        ti = "" +\
        "\nset interfaces st0 unit %s description \"%s\"" % (self.vpn_tunnel_definition["secure_interface"], self.vpn_general["description"]) +\
        "\nset interfaces st0 unit %s family inet" % self.vpn_tunnel_definition["secure_interface"] +\
        "\nset security zones security-zone DMZ_VPN interfaces st0.%s" % self.vpn_tunnel_definition["secure_interface"]

        return ti

    def tunel_interface_delete(self):
        ti = "" +\
        "\ndelete interfaces st0 unit %s" % self.vpn_tunnel_definition["secure_interface"] +\
        "\ndelete security zones security-zone DMZ_VPN interfaces st0.%s" % self.vpn_tunnel_definition["secure_interface"]

        return ti

#STATIC ROUTE
    def static_route(self):
        comando = ""
        for ip in self.encryption_domains["remote"]:
            comando = comando + "\n" + "set routing-options static route %s next-hop st0.%s" % (ip.get("net"),
            self.vpn_tunnel_definition["secure_interface"])
        return comando

    def static_route_delete(self):
        comando = ""
        for ip in self.encryption_domains["remote"]:
            comando = comando + "\n" + "delete routing-options static route %s next-hop st0.%s" % (ip.get("net"),
            self.vpn_tunnel_definition["secure_interface"])
        return comando

#MODIFYING PREFIX-LIST TO PROCESS THE NEW VPN TRAFFIC
    def prefix_list(self):
        comando = ""
        for ip in self.nat_encryption_domains["remote"]: comando = comando + "\n" + "set policy-options prefix-list PBR_Inet-0 %s" % ip.get("net")
        return comando

    def prefix_list_delete(self):
        comando = ""
        for ip in self.nat_encryption_domains["remote"]: comando = comando + "\n" + "delete policy-options prefix-list PBR_Inet-0 %s" % ip.get("net")
        return comando

#NATs

##OUTBOUND TRAFFIC FROM MELI TO REMOTE-ENDPOINTS:

    def outbound_dnat_pool(self):
        command = ""

        self.outbound_dnat_pool_names = {}

        for env in self.encryption_domains["remote"]:
            pool_name = "%s_%s" % (self.vpn_general["name"], env["env"])
            if len(pool_name) <= 31:
                command = command + "\nset security nat destination pool %s_%s address %s" % \
                (self.vpn_general["name"], env["env"], env["net"])
                self.outbound_dnat_pool_names[env["env"]] = "%s_%s" % (self.vpn_general["name"], env["env"])
            else:
                raise ValueError("Pool_name: %s is too long, it must not be longer than 31 characters and it contains %s" % (pool_name, len(pool_name)))

        return command

    def outbound_dnat_pool_delete(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security nat destination pool %s_%s" % \
            (self.vpn_general["name"], env["env"])

        return command

    def outbound_dnat(self):
        command = ""

        for env in self.snat_pools:
            for pool in env["nets"]:
                command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s match source-address %s" % \
                (self.vpn_general["name"], env["env"], pool)

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s then destination-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.outbound_dnat_pool_names[env["env"]])

        return command

    def outbound_dnat_delete(self):
        command = ""

        for env in self.snat_pools:
            command = command + "\ndelete security nat destination rule-set DNAT_FROM_INSIDE rule %s_%s" % \
                (self.vpn_general["name"], env["env"])

        return command

    def outbound_source_pool(self):
        snat_pools = ""

        self.snat_pools_names = {}

        for ip in self.encryption_domains["local"]:
            snat_pools = snat_pools + "\nset security nat source pool %s_%s address %s" % (self.vpn_general["name"], ip.get("env"), ip.get("net"))
            self.snat_pools_names[ip.get("env")] = "%s_%s" % (self.vpn_general["name"], ip.get("env"))

        return snat_pools

    def outbound_source_pool_delete(self):
        snat_pools = ""

        for ip in self.encryption_domains["local"]:
            snat_pools = snat_pools + "\ndelete security nat source pool %s_%s" % (self.vpn_general["name"], ip.get("env"))

        return snat_pools

    def outbound_snat(self):
        command = ""

        for env in self.snat_pools:
            for pool in env["nets"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match source-address %s" % \
            (self.vpn_general["name"], env["env"], pool)

        for env in self.encryption_domains["remote"]:
            rule_name = "%s-%s" % (self.vpn_general["name"], env["env"])
            if len(rule_name) <= 31:
                command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match destination-address %s" % \
             (self.vpn_general["name"], env["env"], env["net"])
            else:
                raise ValueError("Rule_name: %s is too long, it must not be longer than 31 characters and it contains %s" % (rule_name, len(rule_name)))

        for env in self.ports["dports"]:
            command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.encryption_domains["local"]: command = command + "\nset security nat source rule-set NAT_SRC_VPN rule %s-%s then source-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.snat_pools_names[env["env"]])

        return command

    def outbound_snat_delete(self):
        command = ""

        for env in self.snat_pools:
            command = command + "\ndelete security nat source rule-set NAT_SRC_VPN rule %s-%s" %  (self.vpn_general["name"], env["env"])

        return command

##INBOUND TRAFIC FROM CLIENT TO MELI:

    def inbound_dnat_pool(self):
        dpools = ""

        self.dnat_pool_names = {}

        for env in self.local_server:
            dpools = dpools + "\nset security nat destination pool %s_%s_%s address %s" % \
            (self.vpn_general["name"], env["env"], env["server"].replace(".", "_").split("/")[0], env["server"])
            self.dnat_pool_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["server"].replace(".", "_").split("/")[0])

        return dpools

    def inbound_dnat_pool_delete(self):
        dpools = ""

        for env in self.local_server:
            dpools = dpools + "\ndelete security nat destination pool %s_%s_%s" % \
            (self.vpn_general["name"], env["env"], env["server"].replace(".", "_").split("/")[0])

        return dpools


    def inbound_dnat(self):
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

        return command

    def inbound_dnat_delete(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security nat destination rule-set NAT_DEST_VPN rule %s_%s" % \
            (self.vpn_general["name"], env["env"])

        return command

##SOURCE NAT FOR INBOUND TRAFFIC

    def inbound_source_pool(self):
        inbound_spools = ""

        self.inbound_spools_names = {}

        for env in self.nat_encryption_domains["remote"]:
            source_pool_name = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0])
            if source_pool_name <= 31:
                inbound_spools = inbound_spools + "\nset security nat source pool %s_%s_%s address %s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0], env["net"])
                self.inbound_spools_names[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0])
            else:
                raise ValueError("Source pool name: %s is too long, it must not be longer than 31 characters and it contains %s" % (source_pool_name, len(source_pool_name)))

        return inbound_spools

    def inbound_source_pool_delete(self):
        inbound_spools = ""

        for env in self.nat_encryption_domains["remote"]:
            inbound_spools = inbound_spools + "\ndelete security nat source pool %s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"].replace(".", "_").split("/")[0])

        return inbound_spools

    def inbound_snat(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s match source-address %s" % \
            (self.vpn_general["name"], env["env"], env["net"])

        for env in self.local_server:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s match destination-address %s" % \
            (self.vpn_general["name"], env["env"], env["server"])

        for env in self.ports["lports"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s match destination-port %s" % \
            (self.vpn_general["name"], env["env"], env["port"])

        for env in self.nat_encryption_domains["remote"]:
            command = command + "\nset security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s then source-nat pool %s" % \
            (self.vpn_general["name"], env["env"], self.inbound_spools_names[env["env"]])

        return command

    def inbound_snat_delete(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security nat source rule-set SNAT_VPN_TO_B2B rule %s_%s" % \
            (self.vpn_general["name"], env["env"])

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

    def applications_local(self):
        command = ""

        self.applications_names_local = {}

        for app in self.ports["lports"]:
            command = command + "\nset applications application %s-%s-LPORT-TCP-%s protocol tcp" % (self.vpn_general["name"], app["name"], app["port"])
            command = command + "\nset applications application %s-%s-LPORT-TCP-%s destination-port %s" % (self.vpn_general["name"], app["name"], app["port"], app["port"])
            self.applications_names_local[app["env"]] = "%s-%s-LPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])

        return command

    def applications_local_delete(self):
        command = ""

        for app in self.ports["lports"]:
            command = command + "\ndelete applications application %s-%s-LPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])

        return command

    def applications_remote(self):
        command = ""

        self.applications_names_remote = {}

        for app in self.ports["dports"]:
            command = command + "\nset applications application %s-%s-RPORT-TCP-%s protocol tcp" % (self.vpn_general["name"], app["name"], app["port"])
            command = command + "\nset applications application %s-%s-RPORT-TCP-%s destination-port %s" % (self.vpn_general["name"], app["name"], app["port"], app["port"])
            self.applications_names_remote[app["env"]] = "%s-%s-RPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])

        return command

    def applications_remote_delete(self):
        command = ""

        for app in self.ports["dports"]:
            command = command + "\ndelete applications application %s-%s-RPORT-TCP-%s" % (self.vpn_general["name"], app["name"], app["port"])

        return command

    def address_book_dmz_b2b(self):
        command = ""

        self.address_book_dmz_b2b = []

        for env in self.snat_pools:
            for source in env["nets"]:
                command = command + "\nset security zones security-zone DMZ_B2B address-book address %s_%s_%s %s" % \
                (env["name"], env["env"], source, source)
                self.address_book_dmz_b2b.append({env["env"] : "%s_%s_%s" % (env["name"], env["env"], source)})

        return command

    def address_book_dmz_b2b_server(self):
        command = ""

        self.address_book_dmz_b2b_server = {}

        for env in self.local_server:
            command = command + "\nset security zones security-zone DMZ_B2B address-book address %s_%s_%s %s" % \
            (env["name"], env["env"], env["server"], env["server"])
            self.address_book_dmz_b2b_server[env["env"]] = "%s_%s_%s" % (env["name"], env["env"], env["server"])

        return command

    def address_book_dmz_vpn(self):
        command = ""

        self.address_book_dmz_vpn = {}

        for env in self.encryption_domains["remote"]:
            command = command + "\nset security zones security-zone DMZ_VPN address-book address %s_%s_%s %s" % \
            (self.vpn_general["name"], env["env"], env["net"], env["net"])
            self.address_book_dmz_vpn[env["env"]] = "%s_%s_%s" % (self.vpn_general["name"], env["env"], env["net"])

        return command

    def address_book_dmz_b2b_delete(self):
        command = ""

        self.address_book_dmz_b2b = []

        for env in self.snat_pools:
            for source in env["nets"]:
                command = command + "\ndelete security zones security-zone DMZ_B2B address-book address %s_%s_%s" % \
                (env["name"], env["env"], source)

        return command

    def address_book_dmz_b2b_server_delete(self):
        command = ""

        self.address_book_dmz_b2b_server = {}

        for env in self.local_server:
            command = command + "\ndelete security zones security-zone DMZ_B2B address-book address %s_%s_%s" % \
            (env["name"], env["env"], env["server"])

        return command

    def address_book_dmz_vpn_delete(self):
        command = ""

        self.address_book_dmz_vpn = {}

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security zones security-zone DMZ_VPN address-book address %s_%s_%s" % \
            (self.vpn_general["name"], env["env"], env["net"])

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
            command = command + "\nset security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS then log session-init" % \
            (self.vpn_general["name"], env["env"])

        return command

    def outbound_delete(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security policies from-zone DMZ_B2B to-zone DMZ_VPN policy ACCESS_TO_%s_%s_SERVERS" % \
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
            command = command + "\nset security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s then log session-init" % (self.vpn_general["name"], env["env"])

        return command

    def inbound_delete(self):
        command = ""

        for env in self.encryption_domains["remote"]:
            command = command + "\ndelete security policies from-zone DMZ_VPN to-zone DMZ_B2B policy ACCESS_FROM_%s_%s" % \
            (self.vpn_general["name"], env["env"])

        return command

def print_help(ctx, value):
    if value is False:
        click.echo(ctx.get_help())

@click.command()
@click.option('--delete', default=None, help='If you want to delete a VPN already configured with the params inside the json_config file. You should use "in", "out" or "in_and_out" as possible parameters, as example, --delete in')
@click.option('--inbound', is_flag=True, help='If you want to create a VPN with inbound traffic only')
@click.option('--outbound', is_flag=True, help='If you want to create a VPN with outbound traffic only')
@click.option('--in_and_out', is_flag=True, help='If you want to create a VPN with inbound and outbound traffic')
@click.pass_context

def main(ctx, delete, inbound, outbound, in_and_out):
    if delete == None and (inbound is False and outbound is False and in_and_out is False):
        print("\nNo options passed!\n")
        print_help(ctx, value=False)

    try:
        input_file = open("config.json", "r").read()
        settings = json.loads(input_file)
    except IOError:
        print("config.json doesn't exist")
        return

    new_vpn = vpn(settings)
    new_policy = policy(settings)

    if delete == "in_and_out":
        print(new_vpn.phase_1_delete())
        print(new_vpn.phase_2_delete())
        print(new_vpn.gateway_delete())
        print(new_vpn.vpn_delete())
        print(new_vpn.tunel_interface_delete())
        print(new_vpn.static_route_delete())
        print(new_vpn.prefix_list_delete())
        print(new_vpn.outbound_dnat_pool_delete())
        print(new_vpn.outbound_dnat_delete())
        print(new_vpn.source_pool_delete())
        print(new_vpn.outbound_snat_delete())
        print(new_vpn.inbound_dnat_pool_delete())
        print(new_vpn.inbound_dnat_delete())
        print(new_vpn.inbound_source_pool_delete())
        print(new_vpn.inbound_snat_delete())
        print(new_policy.applications_local_delete())
        print(new_policy.applications_remote_delete())
        print(new_policy.address_book_dmz_b2b_delete())
        print(new_policy.address_book_dmz_b2b_server_delete())
        print(new_policy.address_book_dmz_vpn_delete())
        print(new_policy.outbound_delete())
        print(new_policy.inbound_delete())
    elif delete == "in":
        print(new_vpn.phase_1_delete())
        print(new_vpn.phase_2_delete())
        print(new_vpn.gateway_delete())
        print(new_vpn.vpn_delete())
        print(new_vpn.tunel_interface_delete())
        print(new_vpn.static_route_delete())
        print(new_vpn.prefix_list_delete())
        print(new_vpn.inbound_dnat_pool_delete())
        print(new_vpn.inbound_dnat_delete())
        print(new_vpn.inbound_source_pool_delete())
        print(new_vpn.inbound_snat_delete())
        print(new_policy.applications_local_delete())
        print(new_policy.address_book_dmz_b2b_server_delete())
        print(new_policy.address_book_dmz_vpn_delete())
        print(new_policy.inbound_delete())
    elif delete == "out":
        print(new_vpn.phase_1_delete())
        print(new_vpn.phase_2_delete())
        print(new_vpn.gateway_delete())
        print(new_vpn.vpn_delete())
        print(new_vpn.tunel_interface_delete())
        print(new_vpn.static_route_delete())
        print(new_vpn.prefix_list_delete())
        print(new_vpn.outbound_dnat_pool_delete())
        print(new_vpn.outbound_dnat_delete())
        print(new_vpn.outbound_source_pool_delete())
        print(new_vpn.outbound_snat_delete())
        print(new_policy.applications_remote_delete())
        print(new_policy.address_book_dmz_b2b_delete())
        print(new_policy.address_book_dmz_vpn_delete())
        print(new_policy.outbound_delete())
    elif inbound:
        print(new_vpn.phase_1())
        print(new_vpn.phase_2())
        print(new_vpn.gateway())
        print(new_vpn.vpn())
        print(new_vpn.tunel_interface())
        print(new_vpn.static_route())
        print(new_vpn.prefix_list())
        print(new_vpn.inbound_dnat_pool())
        print(new_vpn.inbound_dnat())
        print(new_vpn.inbound_source_pool())
        print(new_vpn.inbound_snat())
        print(new_policy.applications_local())
        print(new_policy.address_book_dmz_b2b_server())
        print(new_policy.address_book_dmz_vpn())
        print(new_policy.inbound())
    elif outbound:
        print(new_vpn.phase_1())
        print(new_vpn.phase_2())
        print(new_vpn.gateway())
        print(new_vpn.vpn())
        print(new_vpn.tunel_interface())
        print(new_vpn.static_route())
        print(new_vpn.prefix_list())
        print(new_vpn.outbound_dnat_pool())
        print(new_vpn.outbound_dnat())
        print(new_vpn.outbound_source_pool())
        print(new_vpn.outbound_snat())
        print(new_policy.applications_remote())
        print(new_policy.address_book_dmz_b2b())
        print(new_policy.address_book_dmz_vpn())
        print(new_policy.outbound())
    elif in_and_out:
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
        print(new_vpn.outbound_snat())
        print(new_vpn.inbound_dnat_pool())
        print(new_vpn.inbound_dnat())
        print(new_vpn.inbound_source_pool())
        print(new_vpn.inbound_snat())
        print(new_policy.applications_local())
        print(new_policy.applications_remote())
        print(new_policy.address_book_dmz_b2b())
        print(new_policy.address_book_dmz_b2b_server())
        print(new_policy.address_book_dmz_vpn())
        print(new_policy.outbound())
        print(new_policy.inbound())

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print (e)
