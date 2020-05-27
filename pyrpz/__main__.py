#!/usr/bin/env python

import pyrpz

if __name__ == "__main__":
    p = pyrpz.PyRPZ()
    try:
        p.run()
    except (KeyboardInterrupt, SystemExit):
        raise
    finally:
        p.close_files()

