"""FreeRADIUS 3.2 rlm_python3 callbacks; secrets stay in the embedded process."""
import radiusd
from downstream_helper import MariaDB, Request, decide


def _attrs(p, required):
    if not isinstance(p, tuple):
        raise ValueError('expected request tuples')
    found = {}
    for pair in p:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ValueError('invalid request pair')
        key, value = pair
        if key in required:
            if key in found or not isinstance(value, str):
                raise ValueError('duplicate or non-text required attribute')
            found[key] = value
    if not all(found.get(key) for key in required):
        raise ValueError('missing request context')
    return found


def authorize(p):
    """For validated duplicate only: remote accept permits subsequent local PAP."""
    db = None
    try:
        attrs = _attrs(p, ('Tmp-String-0', 'User-Name', 'User-Password'))
        db = MariaDB()
        decision = decide(db, attrs['Tmp-String-0'],
                          Request('auth', attrs['User-Name'], attrs['User-Password'], auth=list(p)))
        return radiusd.RLM_MODULE_OK if decision == 'accept' else radiusd.RLM_MODULE_REJECT
    except Exception:
        return radiusd.RLM_MODULE_REJECT
    finally:
        if db is not None:
            db.close()


def preacct(p):
    """Verify an accounting response before allowing local SQL persistence."""
    db = None
    try:
        attrs = _attrs(p, ('Tmp-String-0', 'Acct-Status-Type'))
        if not all(isinstance(pair, tuple) and len(pair) == 2 and
                   all(isinstance(value, str) for value in pair) for pair in p):
            return radiusd.RLM_MODULE_REJECT
        names = [name for name, _ in p]
        status = attrs['Acct-Status-Type']
        if (names.count('User-Name') > 1 or names.count('Acct-Session-Id') > 1 or
                status not in ('Accounting-On', 'Accounting-Off') and
                (names.count('User-Name') != 1 or names.count('Acct-Session-Id') != 1)):
            return radiusd.RLM_MODULE_REJECT
        db = MariaDB()
        decision = decide(db, attrs['Tmp-String-0'],
                          Request('acct', next((value for name, value in p if name == 'User-Name'), ''),
                                  accounting=[pair for pair in p if pair[0] != 'Tmp-String-0']))
        return radiusd.RLM_MODULE_OK if decision == 'accept' else radiusd.RLM_MODULE_REJECT
    except Exception:
        return radiusd.RLM_MODULE_REJECT
    finally:
        if db is not None:
            db.close()


def authenticate(p):
    db = None
    try:
        attrs = _attrs(p, ('Tmp-String-0', 'User-Name', 'User-Password'))
        db = MariaDB()
        decision = decide(db, attrs['Tmp-String-0'],
                          Request('auth', attrs['User-Name'], attrs['User-Password'], auth=list(p)))
        return radiusd.RLM_MODULE_OK if decision == 'accept' else radiusd.RLM_MODULE_REJECT
    except Exception:
        return radiusd.RLM_MODULE_REJECT
    finally:
        if db is not None:
            db.close()
