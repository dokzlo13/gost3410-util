from pyasn1.type import univ, namedtype, tag
from pyasn1.type.char import UTF8String

from strutils import truncate

PRETTY_STRING_LENGTH = 100


class PyasnPrettifierMixin(object):
    own_formatter = True

    def prettyPrint(self, scope=0):
        """Return an object representation string.

        Returns
        -------
        : :class:`str`
            Human-friendly object representation.
        """
        scope += 1
        representation = self.__class__.__name__ + ':\n'
        for idx, componentValue in enumerate(self._componentValues):
            if componentValue is not univ.noValue:
                representation += ' ' * scope
                if self.componentType:
                    representation += self.componentType.getNameByPosition(idx)
                else:
                    representation += self._dynamicNames.getNameByPosition(idx)

                if hasattr(componentValue, 'own_formatter') and componentValue.own_formatter is True:
                    representation = '%s=%s\n' % (
                        representation, componentValue.prettyPrint(scope)
                    )
                else:
                    representation = '%s=%s\n' % (
                        representation, truncate(componentValue.prettyPrint(scope), PRETTY_STRING_LENGTH)
                    )
        return representation


class PrettySet(PyasnPrettifierMixin, univ.Set):
    pass


class PrettySequence(PyasnPrettifierMixin, univ.Sequence):
    pass


class OpenKey(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer())
    )


class CryptosystemParams(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('p', univ.Integer())
    )


class CurveParams(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('a', univ.Integer()),
        namedtype.NamedType('b', univ.Integer())
    )


class DotsParams(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer())
    )


class KeyDataSequence(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('text', UTF8String()),
        namedtype.NamedType('algo', univ.OctetString()),
        namedtype.NamedType('open_key', OpenKey()),
        namedtype.NamedType('cryptosystem_p', CryptosystemParams()),
        namedtype.NamedType('curve_p', CurveParams()),
        namedtype.NamedType('dots_p', DotsParams()),
        namedtype.NamedType('q', univ.Integer())
    )


class KeyDataSet(PrettySet):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keydatasquence', KeyDataSequence())
    )


class SignatureParamsSequence(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )


class FileMetaSequence(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('filesize', univ.Integer()),
        namedtype.NamedType('filename', UTF8String())
    )


class SignatureSequence(PrettySequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('params', KeyDataSet()),
        namedtype.NamedType('sign', SignatureParamsSequence()),
        namedtype.NamedType('meta', FileMetaSequence())

    )
