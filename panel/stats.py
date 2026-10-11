"""Small protobuf client using the upstream StatsService wire format.
Source: SagerNet/sing-box experimental/v2rayapi/stats.proto (v1.14.3).
"""
import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

fd = descriptor_pb2.FileDescriptorProto(name='panel_stats.proto', package='panel', syntax='proto3')
for name, fields in {
    'Query': [('pattern',1,9,False,''), ('reset',2,8,False,'')],
    'Stat': [('name',1,9,False,''), ('value',2,3,False,'')],
    'Response': [('stat',1,11,True,'.panel.Stat')],
}.items():
    m = fd.message_type.add(name=name)
    for key, number, kind, repeated, ref in fields:
        f = m.field.add(name=key, number=number, type=kind, label=3 if repeated else 1)
        if ref:
            f.type_name = ref
pool = descriptor_pool.DescriptorPool()
pool.Add(fd)
Query = message_factory.GetMessageClass(pool.FindMessageTypeByName('panel.Query'))
Response = message_factory.GetMessageClass(pool.FindMessageTypeByName('panel.Response'))

def query(port):
    with grpc.insecure_channel(f'127.0.0.1:{port}') as channel:
        call = channel.unary_unary('/v2ray.core.app.stats.command.StatsService/QueryStats',
                                  request_serializer=Query.SerializeToString,
                                  response_deserializer=Response.FromString)
        return {s.name: s.value for s in call(Query(reset=False), timeout=3).stat}
