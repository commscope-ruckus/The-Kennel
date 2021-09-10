# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: sci-message.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import ap_status_pb2
import ap_report_pb2
import ap_client_pb2
import ap_mesh_pb2
import ap_rogue_pb2
import sci_event_pb2
import sci_configuration_pb2
import ap_avc_pb2
import ap_avc_all_pb2
import sci_alarm_pb2
import ap_wired_client_pb2
import ap_hccd_report_pb2
import sci_pci_pb2
import switch_all_pb2
import switches_pb2
import sci_rogue_pb2
import ap_peerlist_pb2
import session_manager_pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='sci-message.proto',
  package='',
  serialized_pb=_b('\n\x11sci-message.proto\x1a\x0f\x61p_status.proto\x1a\x0f\x61p_report.proto\x1a\x0f\x61p_client.proto\x1a\rap_mesh.proto\x1a\x0e\x61p_rogue.proto\x1a\x0fsci-event.proto\x1a\x17sci-configuration.proto\x1a\x0c\x61p_avc.proto\x1a\x10\x61p_avc_all.proto\x1a\x0fsci-alarm.proto\x1a\x15\x61p_wired_client.proto\x1a\x14\x61p_hccd_report.proto\x1a\rsci-pci.proto\x1a\x10switch_all.proto\x1a\x0eswitches.proto\x1a\x0fsci-rogue.proto\x1a\x11\x61p_peerlist.proto\x1a\x15session_manager.proto\"\xb0\x08\n\nSciMessage\x12\x0f\n\x07version\x18\x01 \x01(\t\x12\x0c\n\x04uuid\x18\x03 \x01(\x0c\x12\x12\n\nsentTimeMs\x18\x04 \x01(\x03\x12\x13\n\x0bsciSystemId\x18\x05 \x01(\t\x12\x1b\n\x08\x61pStatus\x18\x65 \x01(\x0b\x32\t.APStatus\x12 \n\x08\x61pReport\x18\x66 \x01(\x0b\x32\x0e.APReportStats\x12 \n\x08\x61pClient\x18g \x01(\x0b\x32\x0e.APClientStats\x12\x1c\n\x06\x61pMesh\x18h \x01(\x0b\x32\x0c.APMeshStats\x12\x1e\n\x07\x61pRogue\x18i \x01(\x0b\x32\r.RogueAPStats\x12#\n\x0c\x65ventMessage\x18j \x01(\x0b\x32\r.EventMessage\x12\x33\n\x14\x63onfigurationMessage\x18k \x01(\x0b\x32\x15.ConfigurationMessage\x12#\n\x0c\x61larmMessage\x18l \x01(\x0b\x32\r.AlarmMessage\x12*\n\rapWiredClient\x18m \x01(\x0b\x32\x13.APWiredClientStats\x12+\n\x10pciReportMessage\x18n \x01(\x0b\x32\x11.PciReportMessage\x12\x31\n\x13\x61pHccdReportMessage\x18o \x01(\x0b\x32\x14.ApHccdReportMessage\x12I\n\rswitchMessage\x18p \x01(\x0b\x32\x32.com.ruckuswireless.scg.protobuf.icx.SwitchMessage\x12)\n\x0fsciRogueMessage\x18q \x01(\x0b\x32\x10.SciRogueMessage\x12;\n\x18sessionManagerClientData\x18r \x01(\x0b\x32\x19.SessionManagerClientData\x12 \n\narcMessage\x18\xce\x01 \x03(\x0b\x32\x0b.ArcMessage\x12\x1b\n\x05\x61pAvc\x18\xcf\x01 \x01(\x0b\x32\x0b.APAVCStats\x12\x64\n\x1aswitchConfigurationMessage\x18\xac\x02 \x01(\x0b\x32?.com.ruckuswireless.scg.protobuf.icx.SwitchConfigurationMessage\x12X\n\x14realtimeSwitchStatus\x18\xad\x02 \x01(\x0b\x32\x39.com.ruckuswireless.scg.protobuf.icx.RealtimeSwitchStatus\x12\x1e\n\x06\x61pPeer\x18\xae\x02 \x01(\x0b\x32\r.APPeerReport\x12V\n\x13switchDetailMessage\x18\xaf\x02 \x01(\x0b\x32\x38.com.ruckuswireless.scg.protobuf.icx.SwitchDetailMessage*\x06\x08\xe9\x07\x10\xb9\x17\x42\x39\n#com.ruckuswireless.scg.protobuf.sciB\x12SciProtocolMessage')
  ,
  dependencies=[ap_status_pb2.DESCRIPTOR,ap_report_pb2.DESCRIPTOR,ap_client_pb2.DESCRIPTOR,ap_mesh_pb2.DESCRIPTOR,ap_rogue_pb2.DESCRIPTOR,sci_event_pb2.DESCRIPTOR,sci_configuration_pb2.DESCRIPTOR,ap_avc_pb2.DESCRIPTOR,ap_avc_all_pb2.DESCRIPTOR,sci_alarm_pb2.DESCRIPTOR,ap_wired_client_pb2.DESCRIPTOR,ap_hccd_report_pb2.DESCRIPTOR,sci_pci_pb2.DESCRIPTOR,switch_all_pb2.DESCRIPTOR,switches_pb2.DESCRIPTOR,sci_rogue_pb2.DESCRIPTOR,ap_peerlist_pb2.DESCRIPTOR,session_manager_pb2.DESCRIPTOR,])
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_SCIMESSAGE = _descriptor.Descriptor(
  name='SciMessage',
  full_name='SciMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='SciMessage.version', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uuid', full_name='SciMessage.uuid', index=1,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sentTimeMs', full_name='SciMessage.sentTimeMs', index=2,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sciSystemId', full_name='SciMessage.sciSystemId', index=3,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apStatus', full_name='SciMessage.apStatus', index=4,
      number=101, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apReport', full_name='SciMessage.apReport', index=5,
      number=102, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apClient', full_name='SciMessage.apClient', index=6,
      number=103, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apMesh', full_name='SciMessage.apMesh', index=7,
      number=104, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apRogue', full_name='SciMessage.apRogue', index=8,
      number=105, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='eventMessage', full_name='SciMessage.eventMessage', index=9,
      number=106, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='configurationMessage', full_name='SciMessage.configurationMessage', index=10,
      number=107, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='alarmMessage', full_name='SciMessage.alarmMessage', index=11,
      number=108, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apWiredClient', full_name='SciMessage.apWiredClient', index=12,
      number=109, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pciReportMessage', full_name='SciMessage.pciReportMessage', index=13,
      number=110, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apHccdReportMessage', full_name='SciMessage.apHccdReportMessage', index=14,
      number=111, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='switchMessage', full_name='SciMessage.switchMessage', index=15,
      number=112, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sciRogueMessage', full_name='SciMessage.sciRogueMessage', index=16,
      number=113, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sessionManagerClientData', full_name='SciMessage.sessionManagerClientData', index=17,
      number=114, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='arcMessage', full_name='SciMessage.arcMessage', index=18,
      number=206, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apAvc', full_name='SciMessage.apAvc', index=19,
      number=207, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='switchConfigurationMessage', full_name='SciMessage.switchConfigurationMessage', index=20,
      number=300, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='realtimeSwitchStatus', full_name='SciMessage.realtimeSwitchStatus', index=21,
      number=301, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='apPeer', full_name='SciMessage.apPeer', index=22,
      number=302, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='switchDetailMessage', full_name='SciMessage.switchDetailMessage', index=23,
      number=303, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  is_extendable=True,
  extension_ranges=[(1001, 3001), ],
  oneofs=[
  ],
  serialized_start=348,
  serialized_end=1420,
)

_SCIMESSAGE.fields_by_name['apStatus'].message_type = ap_status_pb2._APSTATUS
_SCIMESSAGE.fields_by_name['apReport'].message_type = ap_report_pb2._APREPORTSTATS
_SCIMESSAGE.fields_by_name['apClient'].message_type = ap_client_pb2._APCLIENTSTATS
_SCIMESSAGE.fields_by_name['apMesh'].message_type = ap_mesh_pb2._APMESHSTATS
_SCIMESSAGE.fields_by_name['apRogue'].message_type = ap_rogue_pb2._ROGUEAPSTATS
_SCIMESSAGE.fields_by_name['eventMessage'].message_type = sci_event_pb2._EVENTMESSAGE
_SCIMESSAGE.fields_by_name['configurationMessage'].message_type = sci_configuration_pb2._CONFIGURATIONMESSAGE
_SCIMESSAGE.fields_by_name['alarmMessage'].message_type = sci_alarm_pb2._ALARMMESSAGE
_SCIMESSAGE.fields_by_name['apWiredClient'].message_type = ap_wired_client_pb2._APWIREDCLIENTSTATS
_SCIMESSAGE.fields_by_name['pciReportMessage'].message_type = sci_pci_pb2._PCIREPORTMESSAGE
_SCIMESSAGE.fields_by_name['apHccdReportMessage'].message_type = ap_hccd_report_pb2._APHCCDREPORTMESSAGE
_SCIMESSAGE.fields_by_name['switchMessage'].message_type = switch_all_pb2._SWITCHMESSAGE
_SCIMESSAGE.fields_by_name['sciRogueMessage'].message_type = sci_rogue_pb2._SCIROGUEMESSAGE
_SCIMESSAGE.fields_by_name['sessionManagerClientData'].message_type = session_manager_pb2._SESSIONMANAGERCLIENTDATA
_SCIMESSAGE.fields_by_name['arcMessage'].message_type = ap_avc_pb2._ARCMESSAGE
_SCIMESSAGE.fields_by_name['apAvc'].message_type = ap_avc_all_pb2._APAVCSTATS
_SCIMESSAGE.fields_by_name['switchConfigurationMessage'].message_type = switches_pb2._SWITCHCONFIGURATIONMESSAGE
_SCIMESSAGE.fields_by_name['realtimeSwitchStatus'].message_type = switches_pb2._REALTIMESWITCHSTATUS
_SCIMESSAGE.fields_by_name['apPeer'].message_type = ap_peerlist_pb2._APPEERREPORT
_SCIMESSAGE.fields_by_name['switchDetailMessage'].message_type = switches_pb2._SWITCHDETAILMESSAGE
DESCRIPTOR.message_types_by_name['SciMessage'] = _SCIMESSAGE

SciMessage = _reflection.GeneratedProtocolMessageType('SciMessage', (_message.Message,), dict(
  DESCRIPTOR = _SCIMESSAGE,
  __module__ = 'sci_message_pb2'
  # @@protoc_insertion_point(class_scope:SciMessage)
  ))
_sym_db.RegisterMessage(SciMessage)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n#com.ruckuswireless.scg.protobuf.sciB\022SciProtocolMessage'))
# @@protoc_insertion_point(module_scope)
