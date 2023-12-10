from pydantic import BaseModel

class CallbackRequestDto(BaseModel):
    Type: str
    OperationId: str
    DataSignature: str
    SignedDataHash: str
    AlgName: str

    def __init__(self, type: str, operation_id: str, data_signature: str, signed_data_hash: str, alg_name: str):
        super().__init__(Type=type, OperationId=operation_id, DataSignature=data_signature, SignedDataHash=signed_data_hash, AlgName=alg_name)  

  