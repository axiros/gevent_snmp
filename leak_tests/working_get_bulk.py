import sys
sys.path.append('.')
import cfg
import async_session
import time

while True:
    sess = async_session.AsyncSession(cfg.good_read)
    sess.open_session()

    sess.get_bulk(map(async_session.oid_str_to_tuple, cfg.read_oids))
    time.sleep(cfg.sleep_time)
