# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ap_wired_client.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='ap_wired_client.proto',
  package='',
  serialized_pb=_b('\n\x15\x61p_wired_client.proto\"\xa1\x04\n\x11\x41PWiredClientInfo\x12\x11\n\tclientMac\x18\x01 \x01(\t\x12\x11\n\tipAddress\x18\x02 \x01(\t\x12\x13\n\x0bipv6Address\x18\x03 \x01(\t\x12\x0c\n\x04vlan\x18\x04 \x01(\x05\x12\x10\n\x08rxFrames\x18\x05 \x01(\x04\x12\x0f\n\x07rxBytes\x18\x06 \x01(\x04\x12\x0f\n\x07rxUcast\x18\x07 \x01(\x04\x12\x0f\n\x07rxMcast\x18\x08 \x01(\x04\x12\x0f\n\x07rxBcast\x18\t \x01(\x04\x12\x0e\n\x06rxDrop\x18\n \x01(\x04\x12\x0f\n\x07rxEapol\x18\x0b \x01(\x04\x12\x15\n\rrxMcastLegacy\x18\x0c \x01(\x04\x12\x10\n\x08txFrames\x18\r \x01(\x04\x12\x0f\n\x07txBytes\x18\x0e \x01(\x04\x12\x0f\n\x07txUcast\x18\x0f \x01(\x04\x12\x0f\n\x07txMcast\x18\x10 \x01(\x04\x12\x0f\n\x07txBcast\x18\x11 \x01(\x04\x12\x0e\n\x06txDrop\x18\x12 \x01(\x04\x12\x0f\n\x07txEapol\x18\x13 \x01(\x04\x12\x32\n\nauthStatus\x18\x14 \x01(\x0e\x32\x1e.APWiredClientInfo.AUTH_STATUS\x12\r\n\x05\x65thIF\x18\x15 \x01(\t\x12\x10\n\x08hostname\x18\x16 \x01(\t\x12\x12\n\ndeviceType\x18\x17 \x01(\x05\x12\x14\n\x0cosVendorType\x18\x18 \x01(\x05\x12\x11\n\tmodelName\x18\x19 \x01(\t\",\n\x0b\x41UTH_STATUS\x12\n\n\x06UNAUTH\x10\x00\x12\x11\n\rAUTHENTICATED\x10\x01\"\x93\x02\n\x12\x41PWiredClientStats\x12\x0f\n\x07version\x18\x01 \x01(\r\x12#\n\x07\x63lients\x18\x02 \x03(\x0b\x32\x12.APWiredClientInfo\x12\x11\n\ttimestamp\x18\x03 \x01(\x04\x12\x12\n\nsampleTime\x18\x04 \x01(\x04\x12\x1b\n\x13\x61ggregationInterval\x18\x05 \x01(\r\x12\x0f\n\x07zone_id\x18\x06 \x01(\t\x12\x11\n\tdomain_id\x18\x07 \x01(\t\x12\x12\n\ndeviceName\x18\x08 \x01(\t\x12\x12\n\napgroup_id\x18\t \x01(\t\x12\x13\n\x0b\x61ptenant_id\x18\n \x01(\t\x12\x0e\n\x06map_id\x18\x0b \x01(\t\x12\x12\n\ncluster_id\x18\x0c \x01(\tB!\n\x1f\x63om.ruckuswireless.scg.protobuf')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)



_APWIREDCLIENTINFO_AUTH_STATUS = _descriptor.EnumDescriptor(
  name='AUTH_STATUS',
  full_name='APWiredClientInfo.AUTH_STATUS',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNAUTH', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AUTHENTICATED', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=527,
  serialized_end=571,
)
_sym_db.RegisterEnumDescriptor(_APWIREDCLIENTINFO_AUTH_STATUS)


_APWIREDCLIENTINFO = _descriptor.Descriptor(
  name='APWiredClientInfo',
  full_name='APWiredClientInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='clientMac', full_name='APWiredClientInfo.clientMac', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ipAddress', full_name='APWiredClientInfo.ipAddress', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ipv6Address', full_name='APWiredClientInfo.ipv6Address', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='vlan', full_name='APWiredClientInfo.vlan', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxFrames', full_name='APWiredClientInfo.rxFrames', index=4,
      number=5, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxBytes', full_name='APWiredClientInfo.rxBytes', index=5,
      number=6, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxUcast', full_name='APWiredClientInfo.rxUcast', index=6,
      number=7, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxMcast', full_name='APWiredClientInfo.rxMcast', index=7,
      number=8, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxBcast', full_name='APWiredClientInfo.rxBcast', index=8,
      number=9, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxDrop', full_name='APWiredClientInfo.rxDrop', index=9,
      number=10, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxEapol', full_name='APWiredClientInfo.rxEapol', index=10,
      number=11, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rxMcastLegacy', full_name='APWiredClientInfo.rxMcastLegacy', index=11,
      number=12, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txFrames', full_name='APWiredClientInfo.txFrames', index=12,
      number=13, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txBytes', full_name='APWiredClientInfo.txBytes', index=13,
      number=14, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txUcast', full_name='APWiredClientInfo.txUcast', index=14,
      number=15, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txMcast', full_name='APWiredClientInfo.txMcast', index=15,
      number=16, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txBcast', full_name='APWiredClientInfo.txBcast', index=16,
      number=17, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txDrop', full_name='APWiredClientInfo.txDrop', index=17,
      number=18, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='txEapol', full_name='APWiredClientInfo.txEapol', index=18,
      number=19, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='authStatus', full_name='APWiredClientInfo.authStatus', index=19,
      number=20, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ethIF', full_name='APWiredClientInfo.ethIF', index=20,
      number=21, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='hostname', full_name='APWiredClientInfo.hostname', index=21,
      number=22, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='deviceType', full_name='APWiredClientInfo.deviceType', index=22,
      number=23, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='osVendorType', full_name='APWiredClientInfo.osVendorType', index=23,
      number=24, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='modelName', full_name='APWiredClientInfo.modelName', index=24,
      number=25, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _APWIREDCLIENTINFO_AUTH_STATUS,
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=26,
  serialized_end=571,
)


_APWIREDCLIENTSTATS = _descriptor.Descriptor(
  name='APWiredClientStats',
  full_name='APWiredClientStats',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='APWiredClientStats.version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='clients', full_name='APWiredClientStats.clients', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='APWiredClientStats.timestamp', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sampleTime', full_name='APWiredClientStats.sampleTime', index=3,
      number=4, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='aggregationInterval', full_name='APWiredClientStats.aggregationInterval', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='zone_id', full_name='APWiredClientStats.zone_id', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='domain_id', full_name='APWiredClientStats.domain_id', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='deviceName', full_name='APWiredClientStats.deviceName', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apgroup_id', full_name='APWiredClientStats.apgroup_id', index=8,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='aptenant_id', full_name='APWiredClientStats.aptenant_id', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='map_id', full_name='APWiredClientStats.map_id', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cluster_id', full_name='APWiredClientStats.cluster_id', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=574,
  serialized_end=849,
)

_APWIREDCLIENTINFO.fields_by_name['authStatus'].enum_type = _APWIREDCLIENTINFO_AUTH_STATUS
_APWIREDCLIENTINFO_AUTH_STATUS.containing_type = _APWIREDCLIENTINFO
_APWIREDCLIENTSTATS.fields_by_name['clients'].message_type = _APWIREDCLIENTINFO
DESCRIPTOR.message_types_by_name['APWiredClientInfo'] = _APWIREDCLIENTINFO
DESCRIPTOR.message_types_by_name['APWiredClientStats'] = _APWIREDCLIENTSTATS

APWiredClientInfo = _reflection.GeneratedProtocolMessageType('APWiredClientInfo', (_message.Message,), dict(
  DESCRIPTOR = _APWIREDCLIENTINFO,
  __module__ = 'ap_wired_client_pb2'
  # @@protoc_insertion_point(class_scope:APWiredClientInfo)
  ))
_sym_db.RegisterMessage(APWiredClientInfo)

APWiredClientStats = _reflection.GeneratedProtocolMessageType('APWiredClientStats', (_message.Message,), dict(
  DESCRIPTOR = _APWIREDCLIENTSTATS,
  __module__ = 'ap_wired_client_pb2'
  # @@protoc_insertion_point(class_scope:APWiredClientStats)
  ))
_sym_db.RegisterMessage(APWiredClientStats)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\037com.ruckuswireless.scg.protobuf'))
# @@protoc_insertion_point(module_scope)
