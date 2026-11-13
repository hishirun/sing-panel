"""Minimal read-only sing-box V2Ray StatsService client (never reset counters)."""
import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

fd = descriptor_pb2.FileDescriptorProto(name='agent_stats.proto', package='agent_stats', syntax='proto3')
for name, fields in {
    'Query': [('pattern', 1, 9, False, ''), ('reset', 2, 8, False, '')],
    'Stat': [('name', 1, 9, False, ''), ('value', 2, 3, False, '')],
    'Response': [('stat', 1, 11, True, '.agent_stats.Stat')],
}.items():
    message = fd.message_type.add(name=name)
    for key, number, kind, repeated, reference in fields:
        field = message.field.add(name=key, number=number, type=kind, label=3 if repeated else 1)
        if reference:
            field.type_name = reference
pool = descriptor_pool.DescriptorPool()
pool.Add(fd)
Query = message_factory.GetMessageClass(pool.FindMessageTypeByName('agent_stats.Query'))
Response = message_factory.GetMessageClass(pool.FindMessageTypeByName('agent_stats.Response'))


def query(port):
    with grpc.insecure_channel(f'127.0.0.1:{port}') as channel:
        call = channel.unary_unary('/v2ray.core.app.stats.command.StatsService/QueryStats',
                                  request_serializer=Query.SerializeToString,
                                  response_deserializer=Response.FromString)
        return {item.name: item.value for item in call(Query(reset=False), timeout=3).stat}
