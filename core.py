from binascii import hexlify
from os.path import exists, basename

from pyasn1.codec.der import encoder, decoder

from structs import SignatureSequence
from gost import gost341012


def md5sum(data):
    from hashlib import md5
    m = md5()
    m.update(data)
    return m.digest()


def gost34112012256(data):
    from gost.gost341112 import GOST341112
    dgst = GOST341112(digest_size=256)
    dgst.update(data)
    return dgst.digest()


default_dgstr = gost34112012256


class CryptoError(Exception):
    """Base class for all exceptions in this module."""


class DecryptionError(CryptoError):
    """Raised when decryption fails."""


class VerificationError(CryptoError):
    """Raised when verification fails."""


class SigningError(CryptoError):
    """Raised when signature creation fails."""


def create_signature(curve, prv, dgst, filename='', filesize=0):
    signature = gost341012.sign(curve, prv, dgst, 2012)
    pub = gost341012.public_key(curve, prv)
    s = SignatureSequence()

    params = s.getComponentByName('params').getComponentByName('keydatasquence')
    params.setComponentByName('text', 'gostSignKey')
    params.setComponentByName('algo', b'80060700')
    openkey = params.getComponentByName('open_key')
    openkey.setComponentByName('x', pub[0])
    openkey.setComponentByName('y', pub[1])

    cryptoparams = params.getComponentByName('cryptosystem_p')
    cryptoparams.setComponentByName('p', curve.p)

    curveparams = params.getComponentByName('curve_p')
    curveparams.setComponentByName('a', curve.a)
    curveparams.setComponentByName('b', curve.b)

    dotsparams = params.getComponentByName('dots_p')
    dotsparams.setComponentByName('x', curve.x)
    dotsparams.setComponentByName('y', curve.y)

    params.setComponentByName('q', curve.q)

    sign = s.getComponentByName('sign')
    sign.setComponentByName('r', signature[0])
    sign.setComponentByName('s', signature[1])

    metadata = s.getComponentByName('meta')
    metadata.setComponentByName('filename', filename)
    metadata.setComponentByName('filesize', filesize)
    return s


def verify_signature(dgst, s, own_pubkey=None):
    try:
        params = s.getComponentByName('params').getComponentByName('keydatasquence')

        # params.getComponentByName('text')
        if params.getComponentByName('algo', ) != b'80060700':
            raise DecryptionError('Wrong signature identifier')

        openkey_p = params.getComponentByName('open_key')
        pub = int(openkey_p.getComponentByName('x')), int(openkey_p.getComponentByName('y'))

        if own_pubkey and pub != own_pubkey:
            print('\nOpen keys does not match!')
            return False

        p = int(params.getComponentByName('cryptosystem_p').getComponentByName('p'))
        q = int(params.getComponentByName('q'))
        a = int(params.getComponentByName('curve_p').getComponentByName('a'))
        b = int(params.getComponentByName('curve_p').getComponentByName('b'))
        x = int(params.getComponentByName('dots_p').getComponentByName('x'))
        y = int(params.getComponentByName('dots_p').getComponentByName('y'))
        # Curve parameters are the following: p, q, a, b, x, y

        curve = gost341012.GOST3410Curve(p, q, a, b, x, y)

        signature = int(s.getComponentByName('sign').getComponentByName('r')), int(
            s.getComponentByName('sign').getComponentByName('s'))

        # Extracting some metadata
        # metadata = s.getComponentByName('meta')
        # filename = metadata.getComponentByName('filename')
        # filesize = metadata.getComponentByName('filesize')

    except Exception as e:
        raise VerificationError(e)
    else:
        return gost341012.verify(curve, pub, dgst, signature)


def sign_file(path, curve, prv, dgst_f=default_dgstr):
    try:
        with open(path, 'rb') as file:
            data = file.read()
            dgst = dgst_f(data)
            print('Message hash:', str(hexlify(dgst)))

            s = create_signature(curve, prv, dgst, filename=basename(path), filesize=len(data))
            print('\nGenerated ASN.1 file:\n')
            print(s.prettyPrint())
            with open(path + '.sign', 'wb') as sign_f:
                sign_f.write(encoder.encode(s))
    except Exception as e:
        raise SigningError(e)
    else:
        return True


def verify_file(filepath, dgst_f=default_dgstr, sign_path=None, own_pubkey=None):
    if not sign_path:
        sign_path = filepath + '.sign'
        if not exists(sign_path):
            print('\nCant find {0}.sign in folder, please point path to .sign file'.format(basename(filepath)))
            return False

    try:
        with open(filepath, 'rb') as file, open(sign_path, 'rb') as sign_f:
            data = file.read()
            struct, _ = decoder.decode(sign_f.read(), asn1Spec=SignatureSequence())
            print('\nRead ASN.1 file:\n')
            print(struct.prettyPrint())
            dgst = dgst_f(data)
            is_verified = verify_signature(dgst, struct, own_pubkey)

    except VerificationError:
        raise
    except DecryptionError as e:
        raise VerificationError(e)
    except Exception as e:
        raise VerificationError(e)
    else:
        return is_verified


if __name__ == '__main__':
    from os import urandom
    curve_params = gost341012.CURVE_PARAMS["GostR3410_2012_TC26_ParamSetA"]
    curve = gost341012.GOST3410Curve(*curve_params)
    prv_raw = urandom(32)
    prv = gost341012.prv_unmarshal(prv_raw)
    sign_file('./testdata/lorem.txt', curve, prv)
    assert verify_file('./testdata/lorem.txt')
