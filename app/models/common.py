from pydantic import BaseModel

class PersonalData(BaseModel):
    SerialNumber: str
    GivenName: str
    Surname: str
    CommonName: str
    Country: str


    def __init__(self, serial_number: str, given_name: str, surname: str, common_name: str, country: str):
        super().__init__(SerialNumber=serial_number, GivenName=given_name, Surname=surname, CommonName=common_name, Country=country)  