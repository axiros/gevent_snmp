import sys
sys.path.append('.')
import cfg
import async_session

while True:
    sess = async_session.AsyncSession(cfg.timeout_read)
    sess.open_session()

    try:
        sess.get(map(async_session.oid_str_to_tuple, cfg.read_oids))
    except async_session.SNMPTimeoutError:
        pass
