from typing import List, Optional
from pydantic import BaseModel
    
class Header(BaseModel):
    AlgorithmName: str
    Signature: bytes
    def __init__(self, algorithm_name, signature=None):
        super().__init__(AlgorithmName=algorithm_name,Signature=signature)



class ProtoInfo(BaseModel):
    Name: str
    Version: str
    def __init__(self, name, version):
        super().__init__(Name=name, Version=version)

class OperationInfo(BaseModel):
    Type: str
    OperationId: str
    NbfUTC: int
    ExpUTC: int
    Assignee: Optional[List[str]]
    def __init__(self, operation_id, operation_type, nbf_utc, exp_utc, assignee):
        super().__init__(Type=operation_type, OperationId=operation_id, NbfUTC=nbf_utc, ExpUTC=exp_utc, Assignee=assignee)

class ClientInfo(BaseModel):
    ClientId: int
    ClientName: str
    IconURI: str
    Callback: str
    HostName: Optional[List[str]]
    RedirectURI: str
    def __init__(self, client_id, client_name, icon_uri, callback, redirect_uri, host_name):
        super().__init__(ClientId=client_id, ClientName=client_name, IconURI=icon_uri, Callback=callback, HostName=host_name, RedirectURI=redirect_uri)


class DataInfo(BaseModel):
    DataURI: Optional[str]
    AlgName: Optional[str]
    FingerPrint: Optional[str]
    def __init__(self, data_uri=None, alg_name=None, fingerprint=None):  
        super().__init__(DataURI=data_uri, AlgName=alg_name, FingerPrint=fingerprint)
 

class SignableContainer(BaseModel):
    ProtoInfo: ProtoInfo
    OperationInfo: OperationInfo
    ClientInfo: ClientInfo
    DataInfo: DataInfo
    def __init__(self, proto_info, operation_info, client_info, data_info):
        super().__init__(ProtoInfo=proto_info, OperationInfo=operation_info, ClientInfo=client_info, DataInfo=data_info)


class Contract(BaseModel):
    Header: Header
    SignableContainer: SignableContainer
    def __init__(self, header, signable_container):
        super().__init__(Header=header,SignableContainer=signable_container)
