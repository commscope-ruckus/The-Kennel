# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: switch_all.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import switches_pb2 as switches__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='switch_all.proto',
  package='com.ruckuswireless.scg.protobuf.icx',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x10switch_all.proto\x12#com.ruckuswireless.scg.protobuf.icx\x1a\x0eswitches.proto\"\x9b\x05\n\rSwitchMessage\x12\x0f\n\x07version\x18\x01 \x01(\r\x12G\n\x0cswitchStatus\x18\x02 \x01(\x0b\x32\x31.com.ruckuswireless.scg.protobuf.icx.SwitchStatus\x12\x45\n\x0bswitchStats\x18\x03 \x01(\x0b\x32\x30.com.ruckuswireless.scg.protobuf.icx.SwitchStats\x12\x45\n\x0cportStatuses\x18\x04 \x03(\x0b\x32/.com.ruckuswireless.scg.protobuf.icx.PortStatus\x12\x41\n\tportStats\x18\x05 \x03(\x0b\x32..com.ruckuswireless.scg.protobuf.icx.PortStats\x12Z\n\x16\x63onnectedDevicesStatus\x18\x06 \x03(\x0b\x32:.com.ruckuswireless.scg.protobuf.icx.ConnectedDeviceStatus\x12Q\n\x12switchUnitStatuses\x18\x07 \x03(\x0b\x32\x35.com.ruckuswireless.scg.protobuf.icx.SwitchUnitStatus\x12[\n\x16switchClientVisibility\x18\x08 \x03(\x0b\x32;.com.ruckuswireless.scg.protobuf.icx.SwitchClientVisibility\x12S\n\x12switchClientStatus\x18\t \x01(\x0b\x32\x37.com.ruckuswireless.scg.protobuf.icx.SwitchClientStatus')
  ,
  dependencies=[switches__pb2.DESCRIPTOR,])




_SWITCHMESSAGE = _descriptor.Descriptor(
  name='SwitchMessage',
  full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switchStatus', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.switchStatus', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switchStats', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.switchStats', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='portStatuses', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.portStatuses', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='portStats', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.portStats', index=4,
      number=5, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='connectedDevicesStatus', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.connectedDevicesStatus', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switchUnitStatuses', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.switchUnitStatuses', index=6,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switchClientVisibility', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.switchClientVisibility', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='switchClientStatus', full_name='com.ruckuswireless.scg.protobuf.icx.SwitchMessage.switchClientStatus', index=8,
      number=9, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=74,
  serialized_end=741,
)

_SWITCHMESSAGE.fields_by_name['switchStatus'].message_type = switches__pb2._SWITCHSTATUS
_SWITCHMESSAGE.fields_by_name['switchStats'].message_type = switches__pb2._SWITCHSTATS
_SWITCHMESSAGE.fields_by_name['portStatuses'].message_type = switches__pb2._PORTSTATUS
_SWITCHMESSAGE.fields_by_name['portStats'].message_type = switches__pb2._PORTSTATS
_SWITCHMESSAGE.fields_by_name['connectedDevicesStatus'].message_type = switches__pb2._CONNECTEDDEVICESTATUS
_SWITCHMESSAGE.fields_by_name['switchUnitStatuses'].message_type = switches__pb2._SWITCHUNITSTATUS
_SWITCHMESSAGE.fields_by_name['switchClientVisibility'].message_type = switches__pb2._SWITCHCLIENTVISIBILITY
_SWITCHMESSAGE.fields_by_name['switchClientStatus'].message_type = switches__pb2._SWITCHCLIENTSTATUS
DESCRIPTOR.message_types_by_name['SwitchMessage'] = _SWITCHMESSAGE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SwitchMessage = _reflection.GeneratedProtocolMessageType('SwitchMessage', (_message.Message,), {
  'DESCRIPTOR' : _SWITCHMESSAGE,
  '__module__' : 'switch_all_pb2'
  # @@protoc_insertion_point(class_scope:com.ruckuswireless.scg.protobuf.icx.SwitchMessage)
  })
_sym_db.RegisterMessage(SwitchMessage)


# @@protoc_insertion_point(module_scope)
