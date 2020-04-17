"""
Cleaning Cache in LDAP servers in gluu server
Author : Mohammad Abudayyeh
"""

import logging.config
import multiprocessing
import os
import time
from ldap3 import Server, Connection, MODIFY_REPLACE, SUBTREE, core
import datetime
from pygluu.containerlib import get_manager
from pygluu.containerlib.utils import decode_text
from settings import LOGGING_CONFIG
from joblib import Parallel, delayed
import random

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")
manager = get_manager()
user = manager.config.get("ldap_binddn")
password = decode_text(
    manager.secret.get("encoded_ox_ldap_pw"),
    manager.secret.get("encoded_salt"),
)

base_dn = [
    'ou=uma,o=gluu', 'ou=clients,o=gluu', 'ou=authorizations,o=gluu',
    'ou=sessions,o=gluu', 'ou=scopes,o=gluu', 'ou=metrics,o=gluu',
    'ou=tokens,o=gluu'
]

GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
GLUU_CONFIG_KUBERNETES_NAMESPACE = os.environ.get("GLUU_CONFIG_KUBERNETES_NAMESPACE", "gluu")
PROCESS_TIMEOUT = os.environ.get("PROCESS_TIMEOUT", 300)
TOTAL_RUN_TIME = os.environ.get("TOTAL_RUN_TIME", 300)
number_of_ldap_peers = len(manager.config.get("ldap_peers"))
ldap_peers = []
sep = ':1636'
# opendj
ldap_service = GLUU_LDAP_URL.split(sep, 1)[0]
for i in range(number_of_ldap_peers):
    ldap_peers.append(ldap_service + "-" + str(i) + "." + ldap_service + "."
                      + GLUU_CONFIG_KUBERNETES_NAMESPACE + ".svc.cluster.local")

# Attach peer to dn instead of cleaning all dns on all peers.
peer_dn_list = []
if len(ldap_peers) >= len(base_dn):
    for i in range(len(ldap_peers)):
        try:
            dn = base_dn[i]
        except IndexError:
            dn = None
        peer_dn_list.append([ldap_peers[i], dn])
else:
    for dn in base_dn:
        try:
            peer_dn_list.append([random.choice(ldap_peers), dn])
        except IndexError:
            pass


def get_ldap_time_format(dt):
    return '{}{:02d}{:02d}{:02d}{:02d}{:02d}.{}Z'.format(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
                                                         str(dt.microsecond)[:3])


def search_and_delete(ldap_peer):
    if ldap_peer[1]:
        offset = 0
        ldap_server = Server(str(ldap_peer[0]) + ":1636", port=1636, use_ssl=True)
        ldap_conn = Connection(ldap_server, user=user, password=password)
        try:
            conn_bool = ldap_conn.bind()
            if conn_bool:
                logger.info("Connected to backend LDAP")
                t_s = time.time()
                cur_time = get_ldap_time_format(datetime.datetime.now() + datetime.timedelta(seconds=offset))
                search_filter = '(&(|(oxAuthExpiration<={0})(exp<={0}))(del=true))'.format(cur_time)
                logger.info("Searching expired cache entries for {} at {}".format(str(ldap_peer[1]), str(ldap_peer[0])))
                ldap_conn.search(
                    search_base=ldap_peer[1],
                    search_scope=SUBTREE,
                    search_filter=search_filter,
                    # size_limit=1000,
                    attributes=[]

                )
                response = ldap_conn.response
                if response:
                    logger.info(
                        "Deleting {} entries from {} at {}".format(len(response), str(ldap_peer[1]), str(ldap_peer[0])))
                    for e in response:
                        ldap_conn.delete(e['dn'])
                    t_e = time.time()
                    logger.info(
                        "Cleanup {} at {} took {:0.2f}s".format(str(ldap_peer[1]), str(ldap_peer[0]), t_e - t_s))
        except core.exceptions.LDAPSocketOpenError:
            pass


def main():
    try:
        process_start_time = time.time()
        process_run_time = 0
        while process_run_time < TOTAL_RUN_TIME:
            try:
                results = Parallel(n_jobs=-1, backend="multiprocessing", timeout=PROCESS_TIMEOUT)(
                    map(delayed(search_and_delete), peer_dn_list))
                time.sleep(5)
            except multiprocessing.TimeoutError:
                logger.warning("Process has timeout and will be renewed")
            process_end_time = time.time()
            process_run_time = process_end_time - process_start_time

    except KeyboardInterrupt:
        logger.warning("Canceled by user; exiting ...")


if __name__ == "__main__":
    main()
