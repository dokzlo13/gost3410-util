#!/usr/bin/python

from cmd import Cmd
import os

from gost.gost341012 import CURVE_PARAMS, CURVE_PARAMS_TEXT, GOST3410Curve, prv_unmarshal, public_key
from core import verify_file, VerificationError
from core import sign_file, SigningError
from strutils import truncate

curve_params_sequence = ['p', 'q', 'a', 'b', 'x', 'y']
VERSION = '1.0.0'


def _pubkey_warning(method):
    def wrapper(self, *args, **kwargs):
        if hasattr(self, method.__name__) and hasattr(self, 'key'):
            if self.key != '':
                if 'pub' in self.key.keys():
                    return method(self, *args, **kwargs)
                else:
                    print('There is no public key in the pair!')
            else:
                print('No key pair selected!')
    wrapper.__doc__ = method.__doc__
    return wrapper


def _privkey_warning(method):
    def wrapper(self, *args, **kwargs):
        if hasattr(self, method.__name__) and hasattr(self, 'key'):
            if self.key != '':
                if 'priv' in self.key.keys():
                    return method(self, *args, **kwargs)
                else:
                    print('There is no private key in the pair!')
            else:
                print('No key pair selected!')
    wrapper.__doc__ = method.__doc__
    return wrapper


def assert_int(string):
    try:
        num = int(string)
    except ValueError:
        print('Wrong argument!\n')
        return
    else:
        return num

# TODO: add keys store/load support
# def save_key(key, path):
#     with open(path, 'wb') as f:
#         f.write(key.save_pkcs1('DER'))
#
# def load_key(path, type):
#     with open(path, 'rb') as f:
#         try:
#             if type == 'priv':
#                 return PrivateKey.load_pkcs1(f.read(), 'DER')
#             if type == 'pub':
#                 return PublicKey.load_pkcs1(f.read(), 'DER')
#         except PyAsn1Error:
#             return None


class Shell(Cmd):
    intro = 'Welcome to GOST 34.10-2012 signature util v{} shell. Type help or ? to list commands.\n'.format(VERSION)
    prompt = '[] ~# '

    def __init__(self, *args, **kwargs):
        super(Shell, self).__init__(*args, **kwargs)
        self.keys = []
        self.history = []
        self.key = {}

    def do_genkeys(self, arg):
        """
        Generate new keypair: genkeys
        """
        print(' Please, select Curve params:')
        cntr = 1
        for name, data in CURVE_PARAMS_TEXT.items():
            print('\n {0}:'.format(cntr), name)
            for name, item in zip(curve_params_sequence, data):
                print('\t', name, truncate(item))
            cntr += 1

        indx = int(input('\nSelect parameters index: '))
        while indx > len(CURVE_PARAMS.keys()) or indx < 1:
            print('Wrong params set!')
            indx = int(input('Select parameters index:'))

        param_index = list(CURVE_PARAMS.keys())[indx - 1]
        curve_params = CURVE_PARAMS[param_index]
        print('\nYou choose curve param set "{0}"'.format(param_index))
        curve = GOST3410Curve(*curve_params)

        # Key length option is disabled, by default key size is 128 bits
        # keysize = int(input('\nPlease, select keysize (in bits): '))
        # while keysize < 16:
        #     print('Wrong keysize! (must be >16)')
        #     keysize = int(input('Select parameters index:'))
        # keysize = keysize//8

        keysize = 128

        privkey = prv_unmarshal(os.urandom(keysize))
        pubkey = public_key(curve, privkey)

        key = {}
        key['pub'] = pubkey
        key['priv'] = privkey
        key['curve'] = curve

        self.keys.append(key)
        print('\nKeys generated!\n')
        self.do_keylist('')

    def do_use(self, arg):
        """
        Use keys from available: use [keys idx]
        """
        keyindex = int(arg)
        try:
            self.key = self.keys[keyindex - 1]
        except IndexError:
            print('Wrong index!')
            self.key = ''
            self.prompt = '[] ~# '
        else:
            self.prompt = '[keys({0})] ~# '.format(keyindex)

    def do_clear(self, arg):
        """
        Clear currently used keys: clear
        """
        self.key = {}
        self.prompt = '[] ~# '

    def do_delkey(self, arg):
        """
        Delete keys by index: delkey [keys idx]
        """
        if arg == 'all':
            self.keys = []
            self.do_clear('')
            return

        num = assert_int(arg)
        if not num:
            return
        if len(self.keys) < num:
            print('Wrong index!')
            return
        self.keys.pop(num - 1)
        print('Keypair {0} deleted!\n'.format(num))
        # Maybe print available keys again?
        # self.do_keylist('')

    def do_keylist(self, arg):
        """
        List available keys: keylist
        """
        cntr = 1
        for k in self.keys:
            # print('=========================================================')
            print('================== Keypair {0:>5} ========================'.format(cntr))
            # print('=========================================================')
            if 'pub' in k.keys():
                print('Public Key:')
                print('\tX: {0} ({1} bits)'.format(truncate(str(k['pub'][0])), k['pub'][0].bit_length()))
                print('\tY: {0} ({1} bits)'.format(truncate(str(k['pub'][1])), k['pub'][1].bit_length()))
            if 'priv' in k.keys():
                print('Private Key:')
                print('\t{0} ({1} bits)'.format(truncate(str(k['priv'])), k['priv'].bit_length()))
            if 'curve' in k.keys():
                print('Curve:')
                for name, p in zip(curve_params_sequence, k['curve']):
                    print('\t{0}: {1} ({2} bits)'.format(name, truncate(str(p)), p.bit_length()))
            print('\n')
            cntr += 1

    def do_exit(self, arg):
        """
        Exit from app: exit
        """
        return True

    # I\O operations
    @_privkey_warning
    def do_sign(self, arg):
        """
        Create signature (keypair must be selected): sign [filepath] (will create [filepath].sign file in folder)
        """
        path = arg.replace("'", '')
        try:
            sign_file(path, self.key['curve'], self.key['priv'])
        except SigningError as e:
            print('\nError creating signature\n')
            print(e)
        else:
            print('\nSignature created!\n')

    @_pubkey_warning
    def do_verify(self, arg):
        """
        Check signature by open key (keypair must be selected): verify [filepath] [signpath]
        """
        paths = arg.split(' ')
        paths = [i.replace("'", '') for i in paths]

        if self.key:
            own_key = self.key['pub']
        else:
            own_key = None

        try:
            if len(paths) == 2:
                verification = verify_file(paths[0], sign_path=paths[1], own_pubkey=own_key)
            elif len(paths) == 1:
                verification = verify_file(paths[0], own_pubkey=own_key)
            else:
                print('Wrong params!')
                return
            if verification:
                print('\nSignature checking successful!\n')
            else:
                print('\nSignature checking FAILED!\n')
        except VerificationError as e:
            print('\nError checking signature!\n')
            print(e)


if __name__ == '__main__':
    try:
        Shell().cmdloop()
    except KeyboardInterrupt:
        print('Shutting down...')
