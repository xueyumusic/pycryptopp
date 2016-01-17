
from pycryptopp import _import_my_names

# These initializations to None are just to pacify pyflakes, which
# doesn't understand that we have to do some funky import trickery
# below in _import_my_names() in order to get sensible namespaces.
AESGCM=None
Error=None

_import_my_names(globals(), "aesgcm_")

del _import_my_names

