from pydantic import BaseModel
from fastapi import APIRouter
from starlette.requests import Request
from fastapi.responses import HTMLResponse
from app.services.sima_service import get_file 
from app.services.sima_service import callback as service_callback 
from app.services.sima_service import get_app_uri as service_get_app_uri
from app.services.sima_service import get_qr as service_get_qr
from jinja2 import Template
from fastapi.responses import HTMLResponse

router = APIRouter()

@router.get("/getfile", response_model=BaseModel)
async def get_data(request:Request):
    response = await get_file(request)
    return response

@router.post("/callback", response_model=BaseModel)
async def callback(request:Request):
    response = await service_callback(request)
    return response

@router.get("/get_app_uri",response_model=BaseModel )
async def get_app_uri():
    response = await service_get_app_uri()
    return response



@router.get("/get_qr")
async def read_root():
    image_base64 = await service_get_qr()
    
    # Load the template
    with open("./templates/qr.html", "r") as file:
        template_content = file.read()
    template = Template(template_content)
    
    # Render the template with the base64 encoded QR code image
    html_content = template.render(qrcode=image_base64)
    
    return HTMLResponse(content=html_content, status_code=200)


