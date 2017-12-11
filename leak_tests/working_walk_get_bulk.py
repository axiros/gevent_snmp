import sys
sys.path.append('.')
import cfg
import async_session
import time

while True:
    sess = async_session.AsyncSession(cfg.good_read)
    sess.open_session()

    oid = async_session.oid_str_to_tuple('1.3.6.1.2.1.1')
    sess.walk_with_get_bulk(oid, 2)
    time.sleep(cfg.sleep_time)
