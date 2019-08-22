
import sysca


def test_sysca():
    # create ca key and cert
    ca_key = sysca.new_ec_key()
    ca_pub_key = ca_key.public_key()
    ca_info = sysca.CertInfo(subject={'CN': 'TestCA'}, ca=True)
    ca_certobj = sysca.create_x509_cert(ca_key, ca_pub_key, ca_info, ca_info, 365)
    ca_cert = sysca.CertInfo(load=ca_certobj)
    assert ca_cert.ca

    # srv key
    srv_key = sysca.new_rsa_key()
    srv_info = sysca.CertInfo(subject={'CN': 'Server1'})
    srv_req = sysca.create_x509_req(srv_key, srv_info)

    # ca signs
    srv_info2 = sysca.CertInfo(load=srv_req)
    srv_certobj = sysca.create_x509_cert(ca_key, srv_req.public_key(), srv_info2, ca_info, 365)
    srv_cert = sysca.CertInfo(load=srv_certobj)
    assert not srv_cert.ca


def test_same_pubkey():
    k1 = sysca.new_ec_key()
    k2 = sysca.new_ec_key()
    k3 = sysca.new_rsa_key()
    k4 = sysca.new_rsa_key()
    assert sysca.same_pubkey(k1, k1)
    assert sysca.same_pubkey(k2, k2)
    assert sysca.same_pubkey(k3, k3)
    assert sysca.same_pubkey(k4, k4)
    assert not sysca.same_pubkey(k1, k2)
    assert not sysca.same_pubkey(k1, k3)
    assert not sysca.same_pubkey(k3, k1)
    assert not sysca.same_pubkey(k3, k4)


def test_render_name():
    d = [('CN', 'name'), ('O', 'org')]
    assert sysca.render_name(d) == '/CN=name/O=org/'

    d.append(('X', r'x\b/z'))
    w = sysca.render_name(d)
    assert w == '/CN=name/O=org/X=x\\\\b\\/z/'
    assert sysca.parse_dn(w) == d


def test_passthrough():
    key = sysca.new_ec_key()
    info = sysca.CertInfo(
        subject={
            'CN': 'Passing',
            'O': 'OrgName',
            'OU': 'OrgUnit',
            'C': 'CA',
            'L': 'Location',
            'ST': 'State',
            'SN': 'Surname',
            'GN': 'GivenName',
            'T': 'Title',
            'P': 'Pseudonym',
            'GQ': 'GEN_QUAL',
            'DQ': 'DN_QUAL',
            'UID': 'UID',
            'XUID': 'XUID',
            'EMAIL': 'e@mail',
            'SERIAL': 'EV_SERIAL',
            'SA': 'StreetAddr',
            'PA': 'PostalAddr',
            'PC': 'PostalCode',
            'JC': 'CA',
            'JL': 'JurLocation',
            'JST': 'JurState',
        },
        ca=True,
        path_length=3,
        alt_names=[
            'dns:*.www.com',
            'email:root@www.com',
            'ip:127.0.0.1',
            'uri:http://www.com',
            'dn:/CN=sub-dn/BC=foo/BC=bar/',
        ],
        usage=[
            'digital_signature',
            'content_commitment',
            'key_encipherment',
            'data_encipherment',
            'key_agreement',
            'key_cert_sign',
            'crl_sign',
            # xku
            'server',
            'client',
            'code',
            'email',
            'time',
            'ocsp',
            'any',
        ],
        inhibit_any=6,
        require_explicit_policy=2,
        inhibit_policy_mapping=3,
        ocsp_must_staple=True,
        ocsp_must_staple_v2=True,
        ocsp_nocheck=True,
        ocsp_urls=['http://localhost'],
        issuer_urls=['http://localhost'],
        permit_subtrees=['dns:*.www.com'],
        exclude_subtrees=['dns:*.www.net'],
        certificate_policies=[
            '1.1.1',
            '1.1.2:|P=link|',
            '1.1.3:|P=link2|,|P=link3|',
            '1.1.4:|O=org|,|N=1|,|T=txt|',
            '1.1.5:|O=org|N=2:3|T=txt2|',
        ],
    )
    req = sysca.create_x509_req(key, info)
    info2 = sysca.CertInfo(load=req)

    lst1 = []
    lst2 = []
    info.show(lst1.append)
    info2.show(lst2.append)
    lst2.remove('Public key: ec:secp256r1')
    assert lst1 == lst2


