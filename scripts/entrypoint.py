"""
Cleaning Cache in LDAP servers in gluu server
Author : Mohammad Abudayyeh
"""

import logging.config
import os
import time
from ldap3 import Server, Connection, MODIFY_REPLACE, SUBTREE, core
import datetime
from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")


def get_ldap_time_format(dt):
    return '{}{:02d}{:02d}{:02d}{:02d}{:02d}.{}Z'.format(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
                                                         str(dt.microsecond)[:3])


def main():
    manager = get_manager()
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
    GLUU_CONFIG_KUBERNETES_NAMESPACE = os.environ.get("GLUU_CONFIG_KUBERNETES_NAMESPACE", "gluu")
    user = manager.config.get("ldap_binddn")
    number_of_ldap_peers = len(manager.config.get("ldap_peers"))
    ldap_peers = []
    sep = ':1636'
    # opendj
    ldap_service = GLUU_LDAP_URL.split(sep, 1)[0]
    for i in range(number_of_ldap_peers):
        ldap_peers.append(ldap_service + "-" + str(i) + "." + ldap_service + "."
                          + GLUU_CONFIG_KUBERNETES_NAMESPACE + ".svc.cluster.local")


    password = decode_text(
        manager.secret.get("encoded_ox_ldap_pw"),
        manager.secret.get("encoded_salt"),
    )

    base_dn = [
        'ou=uma,o=gluu', 'ou=clients,o=gluu', 'ou=authorizations,o=gluu',
        'ou=sessions,o=gluu', 'ou=scopes,o=gluu', 'ou=metrics,o=gluu',
        'ou=tokens,o=gluu'
    ]

    try:
        for ldap_peer in ldap_peers:
            offset = 0
            ldap_server = Server(str(ldap_peer) + ":1636", port=1636, use_ssl=True)
            ldap_conn = Connection(ldap_server, user=user, password=password)
            try:
                conn_bool = ldap_conn.bind()
                if conn_bool:
                    logger.info("Connected to backend LDAP")
                    for base in base_dn:
                        t_s = time.time()
                        cur_time = get_ldap_time_format(datetime.datetime.now() + datetime.timedelta(seconds=offset))
                        search_filter = '(&(|(oxAuthExpiration<={0})(exp<={0}))(del=true))'.format(cur_time)
                        logger.info("Searching expired cache entries for {} at {}".format(base, str(ldap_peer)))
                        ldap_conn.search(
                            search_base=base,
                            search_scope=SUBTREE,
                            search_filter=search_filter,
                            attributes=[]
                        )
                        response = ldap_conn.response
                        if response:
                            logger.info("Deleting {} entries".format(len(response)))
                            for e in response:
                                ldap_conn.delete(e['dn'])
                            t_e = time.time()
                            logger.info("Cleanup {} took {:0.2f}s".format(base, t_e - t_s))
            except core.exceptions.LDAPSocketOpenError:
                pass

    except KeyboardInterrupt:
        logger.warning("Canceled by user; exiting ...")


if __name__ == "__main__":
    main()
