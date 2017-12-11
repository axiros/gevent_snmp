import sys
sys.path.append('.')
import cfg
import async_session

while True:
    sess = async_session.AsyncSession(cfg.timeout_read)
    sess.open_session()

    oid = async_session.oid_str_to_tuple('1.3.6.1.2.1.1')
    try:
        sess.walk(oid)
    except async_session.SNMPTimeoutError:
        pass
