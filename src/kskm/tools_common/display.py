from typing import List, Union, Sequence

from kskm.common.data import BundleType
import kskm.common

__author__ = 'ft'


def format_bundles_for_humans(bundles: Sequence[BundleType]) -> Sequence[str]:
    """Dump data about request bundles in either a request or a response."""
    res = [_fmt_fields(num='#',
                       inception='Inception',
                       expiration='Expiration',
                       zsk_tags='ZSK Tags',
                       ksk_tag='KSK(CKA_LABEL)')]
    num = 0
    for this in bundles:
        num += 1
        zsk_info: List[str] = []
        ksk_info: List[str] = []
        for key in this.keys:
            if kskm.common.parse_utils.is_zsk_key(key):
                zsk_info += [str(key.key_tag)]
            else:
                signed = False
                for sig in this.signatures:
                    if sig.key_identifier == key.key_identifier:
                        signed = True
                usage = ''
                if kskm.common.parse_utils.is_revoked_key(key):
                    usage += 'R'
                usage += 'S' if signed else 'P'
                ksk_info += ['{}({})/{}'.format(key.key_tag, key.key_identifier, usage)]
        out = _fmt_fields(num=num,
                          inception=this.inception.isoformat().split('+')[0],
                          expiration=this.expiration.isoformat().split('+')[0],
                          zsk_tags=','.join(zsk_info),
                          ksk_tag=','.join(ksk_info),
                          )
        res += [out]
    return res


def _fmt_fields(**kwargs: Union[int, str]) -> str:
    """
    Format key bundle entries for human consumption.

    Example output from old code base that is replicated here:

    #  Inception           Expiration           ZSK Tags      KSK Tag(CKA_LABEL)
    1  2010-04-01T00:00:00 2010-04-15T23:59:59  55138,23763   05017(KSK1)/S
    2  2010-04-11T00:00:00 2010-04-25T23:59:59  55138         05017(KSK1)/S,55186(KSK2)/P
    ...
    """
    return '{num:<2} {inception:19} {expiration:20} {zsk_tags:13} {ksk_tag}'.format(**kwargs)
