import sys
sys.path.append('.')
import cfg
import async_session
import time

while True:
    sess = async_session.AsyncSession(cfg.good_read)
    sess.open_session()

    with sess.clone_session(community='woho') as priv_sess:
        to_set = {
            async_session.oid_str_to_tuple('1.3.6.1.2.1.1.6.0'): ('1', 'i')
        }

        try:
            priv_sess.set_oids(to_set)
        except async_session.SNMPResponseError:
            pass

    time.sleep(0.2)
