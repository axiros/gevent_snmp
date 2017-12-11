import sys
sys.path.append('.')
import cfg
import async_session

while True:
    sess = async_session.AsyncSession(cfg.timeout_read)
    sess.open_session()

    with sess.clone_session(community='woho') as priv_sess:
        to_set = {
            async_session.oid_str_to_tuple('1.3.6.1.2.1.1.6.0'): ('f', 's')
        }

        try:
            priv_sess.set_oids(to_set)
        except async_session.SNMPTimeoutError:
            pass
