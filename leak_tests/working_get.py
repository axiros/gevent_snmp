import sys
sys.path.append('.')
import cfg
import async_session
import time

while True:
    sess = async_session.AsyncSession(cfg.good_read)
    sess.open_session()

    flags = {
        'get_no_such_instance': 1,
        'get_no_such_object': 1
    }

    sess.get(map(async_session.oid_str_to_tuple, cfg.read_oids), flags)
    time.sleep(cfg.sleep_time)
