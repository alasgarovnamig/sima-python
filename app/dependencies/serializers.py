import json
from app.models.contract import Contract, Header, ProtoInfo, OperationInfo, ClientInfo, DataInfo, SignableContainer

class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (Contract, Header, ProtoInfo, OperationInfo, ClientInfo, DataInfo, SignableContainer)):
            return obj.__dict__
        return super().default(obj)