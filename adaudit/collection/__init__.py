"""Optional read-only directory collection.

Collection is deliberately separate from analysis: it produces the same
normalised dataset an offline import produces, and never modifies the
directory. :mod:`adaudit.collection.ldap` requires the optional ``ldap3``
dependency; :mod:`adaudit.collection.sddl` is dependency-free and parses
security descriptors offline.
"""

from .ldap import CollectionError, LDAPSettings, collect

__all__ = ["CollectionError", "LDAPSettings", "collect"]
