from fastapi.responses import JSONResponse
import base64
import uuid
import hashlib
import hmac
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from app.models.contract import Contract,SignableContainer,Header,ProtoInfo,ClientInfo,DataInfo,OperationInfo
from app.models.requests import CallbackRequestDto
from app.models.common import PersonalData

import qrcode
import base64
import io
async def get_file(request):
    #  Request Validation
    valid = await _ts_cert_validation(request.headers.get('ts-cert'),request.headers.get('ts-sign'),await _get_request_path_and_query_string_as_bytes(request))
    if valid == False:
        return JSONResponse(content={"ErrorMessage":"This request has not been addressed by the Sima application"}, status_code=400)
    
    #  tsQuery convert to Sima Contract Object
    contract = await _ts_query_convert_to_contract(request.query_params.get("tsquery"))

    if(contract == None or 
        #  compare your client Id
       contract.SignableContainer.ClientInfo.ClientId != 0 or  
       #  compare your client name
       contract.SignableContainer.ClientInfo.ClientName != "YOUR_CLIENT_NAME" or 
       #  compare your callback Url
       contract.SignableContainer.ClientInfo.Callback != "YOUR_CALLBACK_URL" or 
       #  compare your icon url
       contract.SignableContainer.ClientInfo.IconURI != "YOUR_ICON_URL"
       ):
        return JSONResponse(content={"ErrorMessage":"This request has not been addressed by the Sima application Data"}, status_code=400)
    if(contract.SignableContainer.OperationInfo.Type == "Auth"):
        return JSONResponse(content={"filename":"challange","data":base64.b64encode(uuid.uuid4().bytes).decode('utf-8')}, status_code=200)  
    return JSONResponse(content={"filename":"dummy.pdf","data":"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"}, status_code=200)  

async def callback(request):
    #  Request Validation
    valid = await _ts_cert_validation(request.headers.get('ts-cert'),request.headers.get('ts-sign'),await request.body())
    if valid == False:
        return JSONResponse(content={"status":"falied"}, status_code=400)
    
    #  Request Body
    request_body = await _request_body_convert_to_callback_request(request)

    # Personal Data
    personal_data = await _ts_cert_to_personal_data(request.headers.get('ts-cert'))
    if (
        personal_data == None or
        personal_data.SerialNumber == None or 
        personal_data.GivenName == None or 
        personal_data.Surname == None or 
        personal_data.CommonName == None or 
        personal_data.Country == None 
        ):
        return JSONResponse(content={"status":"falied"}, status_code=400)
    
    return JSONResponse(content={"status":"success"}, status_code=200)

async def get_app_uri():
    operation_id = "10000000000000000000000000001"
    operation_type = "Auth"  # or "Sign"
    contract = await _create_contract(operation_id, operation_type)
    signature = await _create_signature(contract, "yourSecretKey")
    contract.Header.Signature = signature
    encoded_contract = await _encode_contract(contract)
    return JSONResponse(content={"appUrl":f"{'sima://web-to-app?data=<Your Domain example:https://test.az><Your Path example:/sima/getfile/>?tsquery='}{encoded_contract}"}, status_code=200)

async def get_qr():
    operation_id = "10000000000000000000000000001"
    operation_type = "Auth"  # or "Sign"
    contract = await _create_contract(operation_id, operation_type)
    signature = await _create_signature(contract, "yourSecretKey")
    contract.Header.Signature = signature
    encoded_contract = await _encode_contract(contract)
    return await _generate_qr_code(f"{'<Your Domain example: https://scanme.sima.az><Your Path exaample:/Home/GetFile>/?tsquery='}{encoded_contract}")

async def _ts_cert_validation(ts_cert,ts_sign,process_buffer):
    try:
        # Decode the base64-encoded certificate
        cert_bytes = base64.standard_b64decode(ts_cert)

        # Parse the X.509 certificate
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

         # Extract the ECDSA public key from the parsed certificate
        ecdsa_pub_key = cert.public_key()

        # Decode the base64-encoded DER signature
        der_signature = base64.standard_b64decode(ts_sign)

        # Verify the signature using the ECDSA public key
        ecdsa_pub_key.verify( 
            der_signature,
            process_buffer,
            ec.ECDSA(hashes.SHA256()) 
        ) 
        return True
    except Exception as e:
        return False  

async def _ts_cert_to_personal_data(ts_cert):
    try:
        # Decode the base64-encoded certificate
        cert_bytes = base64.standard_b64decode(ts_cert)

        # Parse the X.509 certificate
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        serial_number = given_name = surname = common_name = country = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.SERIAL_NUMBER:
                serial_number = attribute.value
            elif attribute.oid ==x509.NameOID.GIVEN_NAME:
                given_name = attribute.value   
            elif attribute.oid ==x509.NameOID.SURNAME:
                surname = attribute.value  
            elif attribute.oid == x509.NameOID.COMMON_NAME:
                common_name = attribute.value        
            elif attribute.oid == x509.NameOID.COUNTRY_NAME:
                country = attribute.value
        return PersonalData(serial_number,given_name,surname,common_name,country)
    except Exception as e:
        return None 
    
async def _get_request_path_and_query_string_as_bytes(request):
    request_path = request.url.path
    query_string = request.url.query
    request_path_and_query = f"{request_path}/?{query_string}"
    return request_path_and_query.encode('utf-8')

async def _ts_query_convert_to_contract(ts_query):
    try:
        # Decode the base64-encoded query
        byte_array = base64.b64decode(ts_query)
        json_data = byte_array.decode('utf-8')
        return Contract.from_json_to_dictionary(json_data)
    except Exception as e:
        return None

async def _request_body_convert_to_callback_request(request):
    request_body = await request.json()
    return CallbackRequestDto(
        request_body["Type"],
        request_body["OperationId"],
        request_body["DataSignature"],
        request_body["SignedDataHash"],
        request_body["AlgName"])

async def _create_contract(operation_id, operation_type):
    header = Header(algorithm_name="HmacSHA256", signature="")
    proto_info = ProtoInfo(name="web2app", version="1.3")
    operation_info = OperationInfo(
        operation_id=operation_id,
        operation_type=operation_type,
        nbf_utc=int(datetime.utcnow().timestamp()),
        exp_utc=int((datetime.utcnow() + timedelta(hours=6)).timestamp()),
        assignee=[]
    )
    client_info = ClientInfo(
        client_id=1,
        client_name="ScanMe APP",
        icon_uri="Icon Public URL",
        callback="callbackURL",
        redirect_uri="redirectionURL",
        host_name=[]
    )
    data_info = DataInfo()
    signable_container = SignableContainer(
        proto_info=proto_info,
        operation_info=operation_info,
        client_info=client_info,
        data_info=data_info
    )
    return Contract(header=header, signable_container=signable_container)

async def _encode_contract(model):
    return base64.b64encode(model.json().encode('utf-8')).decode('utf-8')

async def _create_signature(model, secret_key):
    json_data = model.SignableContainer.json().encode('utf-8')
    computed_hash = await _compute_sha256_hash(json_data)
    h_mac = await _get_hmac(computed_hash, secret_key.encode('utf-8'))
    return base64.b64encode(h_mac).decode('utf-8')

async def _compute_sha256_hash(input):
    hash_object = hashlib.sha256()
    hash_object.update(input)
    return hash_object.digest()

async def _get_hmac(data, key):
    h_mac = hmac.new(key, data, hashlib.sha256)
    return h_mac.digest()
    
async def _generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    base64_img = base64.b64encode(img_byte_arr).decode()
    return base64_img
