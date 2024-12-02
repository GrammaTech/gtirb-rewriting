# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2024 GrammaTech, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.

import dataclasses
from enum import Enum
from typing import (
    ClassVar,
    Dict,
    Generic,
    Iterator,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from typing_extensions import BinaryIO, Literal, Self, dataclass_transform

from ._encoders import (
    _AddToOpcodeEncoder,
    _Encoder,
    _FusedEncoder,
    _Low6BitsEncoder,
    _StandaloneEncoder,
)

_FieldT = TypeVar("_FieldT")
_OpcodeT = TypeVar("_OpcodeT", bound=Enum)

_ENCODER_KEY = "gtirb_rewriting_encoder"


def _encoded_field(encoder: _Encoder[_FieldT], *args, **kwargs) -> _FieldT:
    metadata = kwargs.setdefault("metadata", {})
    metadata[_ENCODER_KEY] = encoder
    return dataclasses.field(*args, **kwargs)


@dataclass_transform(field_specifiers=(_encoded_field,))
class _OpcodeEncodable(Generic[_OpcodeT]):
    """
    A base class for classes that can be represented as an opcode and
    operands, encoded as bytes.
    """

    @dataclasses.dataclass
    class _PerTypeStorage:
        """
        Storage that is specific to each enum type in use by subclasses.
        """

        simple_opcodes: Dict[
            int, "Type[_OpcodeEncodable]"
        ] = dataclasses.field(default_factory=dict)
        low6_opcodes: Dict[int, "Type[_OpcodeEncodable]"] = dataclasses.field(
            default_factory=dict
        )

        def _verify_unique(self, opcode: int):
            if opcode in self.simple_opcodes or opcode in self.low6_opcodes:
                raise AssertionError(f"{opcode} already registered")

        def register_simple(
            self, opcode: int, encoder: "Type[_OpcodeEncodable]"
        ) -> None:
            self._verify_unique(opcode)
            self.simple_opcodes[opcode] = encoder

        def register_low6(
            self, opcode: int, encoder: "Type[_OpcodeEncodable]"
        ) -> None:
            self._verify_unique(opcode)
            self.low6_opcodes[opcode] = encoder

    _per_type_storage: ClassVar[Dict[type, _PerTypeStorage]] = {}
    _opcode: ClassVar[Optional[int]] = None
    _opcode_type: ClassVar[Optional[type]] = None

    @overload
    def __init_subclass__(
        cls,
        *,
        opcode: _OpcodeT,
    ):
        ...

    @overload
    def __init_subclass__(
        cls,
        *,
        opcode_type: Type[_OpcodeT],
    ):
        ...

    def __init_subclass__(
        cls,
        *,
        opcode: Optional[_OpcodeT] = None,
        opcode_type: Optional[Type[_OpcodeT]] = None,
    ):
        # First turn the class into a dataclass
        dataclasses.dataclass(cls)

        if opcode is not None:
            # If we have a concrete opcode and aren't abstract, register it
            # so that we can find it during decoding.
            storage = cls._per_type_storage.setdefault(
                type(opcode), cls._PerTypeStorage()
            )

            _, fused_encoder = cls._fused_encoder()
            if fused_encoder:
                if isinstance(fused_encoder, _AddToOpcodeEncoder):
                    for i in range(fused_encoder.max_value):
                        storage.register_simple(opcode.value + i, cls)
                elif isinstance(fused_encoder, _Low6BitsEncoder):
                    storage.register_low6(opcode.value, cls)
                else:
                    raise AssertionError("unknown fused encoder")
            else:
                storage.register_simple(opcode.value, cls)

            cls._opcode = opcode.value

        elif opcode_type:
            cls._opcode_type = opcode_type

        else:
            raise AssertionError("must either have a type or an opcode")

    @classmethod
    def _fields_and_encoders(
        cls,
    ) -> Iterator[Tuple[dataclasses.Field, _Encoder]]:
        """
        Iterate over dataclass fields and their associated encoder objects.
        """
        for field in dataclasses.fields(cls):  # type: ignore
            yield field, field.metadata[_ENCODER_KEY]

    @classmethod
    def _fused_encoder(cls):
        for field, encoder in cls._fields_and_encoders():
            if isinstance(encoder, _FusedEncoder):
                return field, encoder
            break

        return (None, None)

    def __post_init__(self):
        """
        Perform post-initialization validation.
        """
        if self._opcode is None:
            name = type(self).__name__
            raise TypeError(f"Can't instantiate abstract class {name}")

        for field, encoder in self._fields_and_encoders():
            value = getattr(self, field.name)
            try:
                encoder.validate(value)
            except ValueError as err:
                raise ValueError(f"{field.name}: {err}") from err

    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> Union[bytes, bytearray]:
        assert self._opcode is not None
        fused_field, fused_encoder = self._fused_encoder()

        if fused_field and fused_encoder:
            value = getattr(self, fused_field.name)
            result = fused_encoder.encode(
                self._opcode, value, byteorder, ptr_size
            )
        else:
            result = self._opcode.to_bytes(1, byteorder)

        for field, encoder in self._fields_and_encoders():
            if isinstance(encoder, _StandaloneEncoder):
                value = getattr(self, field.name)
                result += encoder.encode(value, byteorder, ptr_size)

        return result

    @classmethod
    def decode(
        cls, io: BinaryIO, byteorder: Literal["big", "little"], ptr_size: int
    ) -> Tuple[Self, int]:
        if cls._opcode_type is None:
            name = cls.__name__
            raise TypeError(f"Can't instantiate abstract class {name}")

        type_storage = cls._per_type_storage[cls._opcode_type]

        opcode_byte = int.from_bytes(io.read(1), byteorder)
        bytes_read = 1
        opcode_cls = type_storage.simple_opcodes.get(opcode_byte)
        if opcode_cls is None:
            opcode_cls = type_storage.low6_opcodes.get(opcode_byte & 0xC0)

        if not opcode_cls:
            raise ValueError(f"invalid opcode byte: {opcode_byte}")

        assert issubclass(opcode_cls, cls)

        ctor_args = {}
        fused_field, fused_encoder = opcode_cls._fused_encoder()
        if fused_field and fused_encoder:
            assert opcode_cls._opcode
            ctor_args[fused_field.name] = fused_encoder.decode(
                opcode_cls._opcode, opcode_byte, byteorder, ptr_size
            )

        for field, encoder in opcode_cls._fields_and_encoders():
            if isinstance(encoder, _StandaloneEncoder):
                value, field_byte_count = encoder.decode(
                    io, byteorder, ptr_size
                )
                bytes_read += field_byte_count
                ctor_args[field.name] = value

        return opcode_cls(**ctor_args), bytes_read
