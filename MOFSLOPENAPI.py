import requests
from requests import get
import json
import os
from datetime import datetime, timezone
import sys
import socket
import re, uuid
import hashlib
import platform
# import wmi
import geocoder

import websocket
# import requests
# import json
# import hashlib
# import re, uuid
# from requests import get
# import socket
from struct import *
# import sys
# import os
import time
# from datetime import datetime 
import datetime as dt
from queue import Queue
from threading import Thread



# Constant
# Api-Version
version = "V.1.1.0"

# ErrorLogs
try:
    os.mkdir('Logs')
except FileExistsError:
    null = 0

try:   
    MainPath = os.getcwd()
    os.chdir('Logs')
    LogPath = os.getcwd()
    os.chdir(MainPath)
except:
    print('\nError in Assigning Path!!!')
    sys.exit()


def WriteIntoLog(f_status, f_filename, f_message):
    try:
        dt = datetime.now()
        x = dt.strftime("%Y-%m-%d %H:%M:%S")
        logmessage = str(x) + ("             ") + f_status + ("             ") + f_filename + ("             ") + f_message + "\n"
        os.chdir(LogPath)
        strdate = datetime.now()
        Logfile = open(str(strdate.strftime("%d-%b-%Y")) + "_OpenApiLibrary(python).Log","a+")
        os.chdir(MainPath)
        Logfile.write(logmessage)
        Logfile.close()
    except:
        print('\nError in Writing Logs!!!')
        sys.exit()

def WriteIntoLog_Broadcast(f_status, f_filename, f_message):
    try:
        dt = datetime.now()
        x = dt.strftime("%Y-%m-%d %H:%M:%S")
        logmessage = str(x) + ("             ") + f_status + ("             ") + f_filename + ("             ") + f_message + "\n"
        os.chdir(LogPath)
        strdate = datetime.now()
        Logfile = open(str(strdate.strftime("%d-%b-%Y")) + "_OpenApiBroadcast(python).Log","a+")
        os.chdir(MainPath)
        Logfile.write(logmessage)
        Logfile.close()
    except:
        print('\nError in Writing Logs!!!')
        sys.exit()

def WriteIntoLog_TradeStatus(f_status, f_filename, f_message):
    try:
        dt = datetime.now()
        x = dt.strftime("%Y-%m-%d %H:%M:%S")
        logmessage = str(x) + ("             ") + f_status + ("             ") + f_filename + ("             ") + f_message + "\n"
        os.chdir(LogPath)
        strdate = datetime.now()
        Logfile = open(str(strdate.strftime("%d-%b-%Y")) + "_OpenApiTradeStatus(python).Log","a+")
        os.chdir(MainPath)
        Logfile.write(logmessage)
        Logfile.close()
    except:
        print('\nError in Writing Logs!!!')
        sys.exit()


# def WriteIntoLog(f_status, f_filename, f_message):
#     try:
#         os.mkdir("Logs")        
#     except FileExistsError:
#         null = 0

#     try:   
#         MainPath = os.getcwd()
#         os.chdir('Logs')
#         LogPath = os.getcwd()
#         os.chdir(MainPath)
#     except:
#         print('\nError in Assigning Path!!!')
#         sys.exit()

#     try:
#         dt = datetime.now()
#         x = dt.strftime("%Y-%m-%d %H:%M:%S")
#         logmessage = str(x) + ("             ") + f_status + ("             ") + f_filename + ("             ") + f_message + "\n"
#         os.chdir(LogPath)
#         strdate = datetime.now()
#         Logfile = open(str(strdate.strftime("%d-%b-%Y")) + "_OpenApiLibrary(python).Log","a+")
#         os.chdir(MainPath)
#         Logfile.write(logmessage)
#         Logfile.close()
#     except:
#         print('\nError in Writing Logs!!!')
#         sys.exit()
            


# UserInfo
def GetMacAddress(): 
    try:
        clientMacAddress=':'.join(re.findall('..', '%012x' % uuid.getnode()))
        return clientMacAddress
    except Exception as e:
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetMacAddress" + str(e)))
        print(e)
        return "00:00:00:00:00:00"

def GetLocalIPAddress():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetLocalIPAddress" + str(e)))
        print(e)
        return "1.2.3.4"

def GetPublicIPAddress():
    try:        
        public_ip = get('http://checkip.dyndns.org/').text
        ipaddress=str(re.findall(r'[0-9]+(?:\.[0-9]+){3}',public_ip))

        finalipppp=ipaddress.replace("'","")
        finalipppp=finalipppp.replace("[","")
        finalipppp=finalipppp.replace("]","")
        if not finalipppp:
            finalipppp = "1.2.3.4"
        return finalipppp
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetPublicIPAddress" + str(e)))
        return "1.2.3.4"

# print(GetLocalIPAddress())
# print(GetPublicIPAddress())
# print(GetMacAddress())

# System Info

# c = wmi.WMI()   
# objsystem = c.Win32_ComputerSystem()[0]
# system = platform.uname()

def GetOsName():
    try:        
        # osname = system.system
        osname = "Ubuntu 20.04.3 LTS"
        return osname
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetOsName" + str(e)))
        # return "Win32NT"

def GetOsVersion():
    try:        
        # osversion = system.version
        osversion= "20.04"
        return osversion
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetOsVersion" + str(e)))
        # return "10.0.19044.0"

def GetInstalledAppid():
    try:        
        installedappid = uuid.uuid1()
        return installedappid
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetInstalledAppid" + str(e)))
        # return "10.0.19044.0"

def GetDeviceModel():
    try:   
        # devicemodel = objsystem.Model     
        devicemodel = "VMware Virtual Platform"
        return devicemodel
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetDeviceModel" + str(e)))
        # return "VMware Virtual Platform"

def GetManufacturer():
    try:   
        # manufacturer = objsystem.Manufacturer
        manufacturer = "unknown"
        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", ("GetManufacturer" +manufacturer) )

        if manufacturer==None:
           return "unknown"
        elif len(manufacturer) > 25 or len(manufacturer) < 1:
            return "unknown"
        return manufacturer
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetManufacturer" + str(e)))
        return "unknown"

        # return "Phoenix Technologies LTD"

def GetProductName():
    try:   
        productname = "Investor"
        return productname
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetProductName" + str(e)))
        # return "Investor"

def GetProductVersion():
    try:   
        productversion = "1"
        return productversion
    except Exception as e:
        print(e)
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetProductVersion" + str(e)))
        # return "1"

def GetLatitudeLongitude():
    try:   
        # ipaddress = geocoder.ip('me')
        lst_latlng = [0,0]
        # print(var[0],var[1] )
        if lst_latlng == None:
            lst_latlng = [19.0760, 72.8777]
        return lst_latlng
    except Exception as e:
        WriteIntoLog("FAILED", "MOFSLOPENAPI.py", ("GetLongitudeLatitude" + str(e)))
        ipaddress = geocoder.ip('106.193.137.95') #106.193.137.95
        lst_latlng = ipaddress.latlng
        # print(var[0],var[1] )
        if lst_latlng == None:
            lst_latlng = [19.0760, 72.8777]
        return lst_latlng



class MOFSLOPENAPI(object):

    m_strMOFSLToken=""
    m_strClientPublicIP = ""
    m_strClientLocalIP = ""
    m_strMACAddress = ""
    m_strSourceID = ""  # Web,Desktop,Mobile
    m_strApikey = ""
    m_strApiSecretkey = ""
    m_strUseragent = "MOSL/" + version
    m_Base_Url = ""
    m_vendorinfo = ""
    m_clientcodeDealer = ""

    m_osname = ""
    m_osversion = ""
    m_installedappid = ""
    m_devicemodel = ""
    m_manufacturer = ""
    m_browsername = ""
    m_browserversion = ""
    m_imeino = ""                         #--- In 15digit in strings format eg= "987456321987654"
    m_productname = ""
    m_productversion = ""
    m_latitudelongitude = ""

    m_MaxBroadcastLimit = 0        # self.getbroadcastmaxlimit(self.m_clientcodeDealer)
    m_scriptask = ""
    m_TCPscriptask = ""
    m_indextask = ""
    m_TCPindextask = ""
    l_scrip_code = []
    l_TCPscrip_code = []

    l_exchange_index = []
    l_TCPexchange_index = []
    m_clientcode = ""
    Websocket_version = "VER 2.0"
    q_msg = Queue()

    ws1 = None
    ws2 = None

    # TCPSocket
    s = None 
    AttemptCountSocket = 1 

    m_responsepacketlength = 30
    m_TCPresponsepacketlength = 30
    TradeStatusHeartbeat_flag = True
    BroadcastAutoRelogin_flag = True
    TCPBroadcastAutoRelogin_flag = True
    Broadcast_Logout_flag = True
    TCPBroadcast_Logout_flag = True
    BroadcastAutoRelogin_counter = 1
    TCPBroadcastAutoRelogin_counter = 1
    m_LastMsgTime = 0

    def __init__(self, f_apikey, f_Base_Url, f_clientcode, f_strSourceID, f_browsername, f_browserversion):
        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilize Constructor")

        self.m_strApikey = f_apikey
        self.m_strMACAddress = GetMacAddress()
        self.m_strClientLocalIP = GetLocalIPAddress()
        self.m_strClientPublicIP = GetPublicIPAddress()
        self.m_strSourceID = f_strSourceID
        self.m_strApiSecretkey = self.m_strApiSecretkey
        self.m_Base_Url = f_Base_Url
        self.m_clientcodeDealer = f_clientcode

        self.m_osname = GetOsName()
        self.m_osversion = GetOsVersion()
        self.m_installedappid = str(GetInstalledAppid())
        self.m_devicemodel = GetDeviceModel()
        self.m_manufacturer = GetManufacturer()
        self.m_productname = GetProductName()
        self.m_productversion = GetProductVersion()
        self.m_browsername = f_browsername
        self.m_browserversion = f_browserversion

        self.m_latitudelongitude = GetLatitudeLongitude()

        # self.Websocket_URL = self.Websocket_URL
        # self.l_scrip_code = []
        # self.l_exchange_index = []
        self.Websocket_version = self.Websocket_version

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilize Constructor Done")

    def GetUrl(self, f_ApiPath):
        base_Url= self.m_Base_Url
        # ver = "/rest/v1"

        try:
            if f_ApiPath =="Login":
                # Login URL
                Login_ApiPath = "/rest/login/v4/authdirectapi"
                URL = (str(base_Url)+str(Login_ApiPath))
            
            elif f_ApiPath =="Logout": 
                # Logout URL
                Logout_ApiPath = "/rest/login/v1/logout"
                URL = (str(base_Url)+str(Logout_ApiPath))
                
            elif f_ApiPath =="GetProfile":
                # GetProfile URL
                GetProfile_ApiPath = "/rest/login/v1/getprofile"
                URL = (str(base_Url)+str(GetProfile_ApiPath))

            elif f_ApiPath =="OrderBook":
                # OrderBook URL
                OrderBook_ApiPath = "/rest/book/v1/getorderbook"
                URL = (str(base_Url)+str(OrderBook_ApiPath))

            elif f_ApiPath =="TradeBook":
                # TradeBook URL
                TradeBook_ApiPath = "/rest/book/v1/gettradebook"
                URL = (str(base_Url)+str(TradeBook_ApiPath))

            elif f_ApiPath =="GetPosition":
                # GetPosition URL
                GetPosition_ApiPath = "/rest/book/v1/getposition"
                URL = (str(base_Url)+str(GetPosition_ApiPath))

            elif f_ApiPath =="DPHolding":
                # TradeBook URL
                DPHolding_ApiPath = "/rest/report/v1/getdpholding"
                URL = (str(base_Url)+str(DPHolding_ApiPath))

            elif f_ApiPath =="PlaceOrder":
                # PlaceOrder URL
                PlaceOrder_ApiPath = "/rest/trans/v1/placeorder"
                URL = (str(base_Url)+str(PlaceOrder_ApiPath))

            elif f_ApiPath =="ModifyOrder":
                # ModifyOrder URL
                ModifyOrder_ApiPath = "/rest/trans/v2/modifyorder"
                URL = (str(base_Url)+str(ModifyOrder_ApiPath))

            elif f_ApiPath =="CancelOrder":
                # CancelOrder URL
                CancelOrder_ApiPath = "/rest/trans/v1/cancelorder"
                URL = (str(base_Url)+str(CancelOrder_ApiPath))

            elif f_ApiPath =="positionconversion":
                # positionconversion URL
                positionconversion_ApiPath = "/rest/trans/v1/positionconversion"
                URL = (str(base_Url)+str(positionconversion_ApiPath))

            elif f_ApiPath =="marginreport":
                # MarginReport URL
                marginreport_ApiPath = "/rest/report/v1/getreportmargin"
                URL = (str(base_Url)+str(marginreport_ApiPath))

            elif f_ApiPath =="marginsummary":
                # MarginSummary URL
                marginsummary_ApiPath = "/rest/report/v1/getreportmarginsummary"
                URL = (str(base_Url)+str(marginsummary_ApiPath))

            elif f_ApiPath =="margindetail":
                # MarginDetail URL
                margindetail_ApiPath = "/rest/report/v1/getreportmargindetail"
                URL = (str(base_Url)+str(margindetail_ApiPath))

            elif f_ApiPath =="ltadata":
                # LTA Data URL
                ltadata_ApiPath = "/rest/report/v1/getltpdata"
                URL = (str(base_Url)+str(ltadata_ApiPath))

            elif f_ApiPath =="exchangedata":
                # EXCHANGE DATA URL
                exchangedata_ApiPath = "/rest/report/v1/getscripsbyexchangename"
                URL = (str(base_Url)+str(exchangedata_ApiPath))

            elif f_ApiPath =="getorderdetailbyunqueorderid":
                # Getorderdetailbyunqueorderid
                getorderdetailbyunqueorderid_Apipath = "/rest/book/v1/getorderdetailbyuniqueorderid"
                URL = (str(base_Url)+str(getorderdetailbyunqueorderid_Apipath))

            elif f_ApiPath =="getbrokeragedetail":
                # getbrokeragedetail
                getbrokeragedetail_Apipath = "/rest/report/v1/getbrokeragedetail"
                URL = (str(base_Url)+str(getbrokeragedetail_Apipath))
               
            elif f_ApiPath =="getbroadcastmaxlimit":
                # getbroadcastmaxlimit
                getbroadcastmaxlimit_Apipath = "/rest/report/v1/getbroadcastmaxlimit"
                URL = (str(base_Url)+str(getbroadcastmaxlimit_Apipath))

            elif f_ApiPath =="resendotp":
                # resendotp
                resendotp_Apipath = "/rest/login/v3/resendotp"
                URL = (str(base_Url)+str(resendotp_Apipath))

            elif f_ApiPath =="verifyotp":
                # verifyotp
                verifyotp_Apipath = "/rest/login/v3/verifyotp"
                URL = (str(base_Url)+str(verifyotp_Apipath))

            else:
                print("Error in GetURL")
            
            return URL
        
        except Exception as e:
            print(e) 
 


    def validate(self, f_URL, f_Data):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilize Post WebRequest Sent")

        try:

            m_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization" : self.m_strMOFSLToken,
                "User-Agent" : self.m_strUseragent,
                "apikey": self.m_strApikey, 
                "apisecretkey" : self.m_strApiSecretkey,
                "macaddress": self.m_strMACAddress,
                "clientlocalip": self.m_strClientLocalIP,
                "sourceid": self.m_strSourceID,
                "clientpublicip": self.m_strClientPublicIP,
                "vendorinfo": self.m_vendorinfo,

                "osname": self.m_osname, 
                "osversion" : self.m_osversion,
                "installedappid": self.m_installedappid,
                "devicemodel": self.m_devicemodel,
                "manufacturer": self.m_manufacturer,
                "productname": self.m_productname,
                "productversion": self.m_productversion,

                "latitude": str("%.4f" % self.m_latitudelongitude[0]),
                "longitude": str("%.4f" % self.m_latitudelongitude[1]),
                "sdkversion":"Python 3.0"

                # "browsername": self.m_browsername,
                # "browserversion": self.m_browserversion,
                # "imeino": self.m_imeino

            }

            if self.m_strSourceID.upper() == "WEB":
                m_headers["browsername"] = self.m_browsername
                m_headers["browserversion"] = self.m_browserversion

            # print(m_headers)            
            response = requests.post(f_URL, headers= m_headers, data = json.dumps(f_Data))
            # print("JSON Response ", response.content)
            j_ResponseMessage = response.content.decode('utf-8')

            WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Post WebRequest Send Successfully")
            return j_ResponseMessage

        except Exception as e:
            l_boolisconnect = MOFSLOPENAPI.checkinternet(self)
            if l_boolisconnect == False:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "Network connection is unavailable")

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e))

            return ("POST ERROR " + str(e))

    
    def checkinternet(self):
        url = "https://www.google.co.in"
        timeout = 3
        try:
        # requesting URL
            request = requests.get(url, timeout=timeout)
            return True
  
        # catching exception
        except (requests.ConnectionError, requests.Timeout) as exception:
            return False


    # resendotp API
    def resendotp(self):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize resendotp request send")
        l_resendotpResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "resendotp")
            l_strGetdata = {
                "clientcode" : ""
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "resendotp request sent Successfully")
                l_resendotpResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "resendotp Request failed")

                l_resendotpResponse["status"] = "FAILED"
                l_resendotpResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_resendotpResponse["errorcode"] = "" 
                l_resendotpResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_resendotpResponse["status"] = "FAILED"
            l_resendotpResponse["message"] = str(e)
            l_resendotpResponse["errorcode"] = ""
            l_resendotpResponse["data"] = {"null"}  

        return l_resendotpResponse
    
    # verifyotp API
    def verifyotp(self, f_otp):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize verifyotp request send")
        l_verifyotpResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "verifyotp")
            l_strGetdata = {
                "otp": f_otp
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "verifyotp request sent Successfully")
                l_verifyotpResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "verifyotp Request failed")

                l_verifyotpResponse["status"] = "FAILED"
                l_verifyotpResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_verifyotpResponse["errorcode"] = "" 
                l_verifyotpResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_verifyotpResponse["status"] = "FAILED"
            l_verifyotpResponse["message"] = str(e)
            l_verifyotpResponse["errorcode"] = ""
            l_verifyotpResponse["data"] = {"null"}  

        return l_verifyotpResponse

    # login function with username and password
    def login(self, f_clientID, f_password, f_twoFA, f_totp = None ,f_vendorinfo = None):

        l_loginResponse = {}

        try:
            if f_clientID == "" or f_password == "":
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "login_Client_id or Password is empty")

            else:
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilize login request send")
            
            self.m_vendorinfo = f_vendorinfo
            self.m_clientcode = f_clientID

            f_strallcombine = f_password + self.m_strApikey 
            h = hashlib.sha256(f_strallcombine.encode("utf-8"))
            checksum = h.hexdigest()
            # print(checksum, type(checksum))
            l_PostData = {
                "userid": f_clientID,
                "password": checksum,
                "2FA": f_twoFA ,
                "totp": f_totp                
            } 
            l_URL = MOFSLOPENAPI.GetUrl(self, "Login")
            
            
            l_strJSON = MOFSLOPENAPI.validate(self ,l_URL, l_PostData)

            if "POST ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)
                if l_strDICT["status"] == "SUCCESS" :
                    self.m_strMOFSLToken = l_strDICT["AuthToken"]      
                    WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Login sucessfully")

                else:
                    WriteIntoLog(l_strDICT["status"], "MOFSLOPENAPI.py", l_strDICT["message"])

                l_loginResponse = l_strDICT
                               
            else :
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "login_Error while sending the webRequest")
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "Login Request failed")

                l_loginResponse["status"] = "FAILED"
                l_loginResponse["message"] = l_strJSON.replace("POST ERROR ", "")
                l_loginResponse["errorcode"] = ""  
                l_loginResponse["AuthToken"] = ""   
                                
        except Exception as e:
            l_loginResponse["status"] = "FAILED"
            l_loginResponse["message"] = str(e)
            l_loginResponse["errorcode"] = "" 
            l_loginResponse["AuthToken"] = ""   

        return l_loginResponse   

    def logout(self, f_strclientcode = None):

        l_logoutResponse = {}
        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilize Logout Request")

        l_URL = MOFSLOPENAPI.GetUrl(self, "Logout")
        l_PostData = {
            "userid": f_strclientcode         
        } 

        try:
            l_strJSON = MOFSLOPENAPI.validate(self, l_URL, l_PostData) 
            if "POST ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)
                if l_strDICT["status"] == "SUCCESS" :
                    self.m_strMOFSLToken = ""      
                    WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Logout sucessfully")  
                else:
                    WriteIntoLog(l_strDICT["status"], "MOFSLOPENAPI.py", l_strDICT["message"])

                l_logoutResponse = l_strDICT
            
            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "logout_Error while sending the webRequest")
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "Logout Request failed")

                l_logoutResponse["status"] = "FAILED"
                l_logoutResponse["message"] = l_strJSON.replace("POST ERROR ", "")
                l_logoutResponse["errorcode"] = ""   
                                    
        except Exception as e :

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e))

            l_logoutResponse["status"] = "FAILED"
            l_logoutResponse["message"] = str(e)
            l_logoutResponse["errorcode"] = ""  

        return l_logoutResponse 

    def GetProfile(self, f_strclientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetProfile request send")
        l_GetProfileResponse = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "GetProfile")
            l_strGetdata = {
                "clientcode": f_strclientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetProfile request sent Successfully")
                l_GetProfileResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetProfile Request failed")

                l_GetProfileResponse["status"] = "FAILED"
                l_GetProfileResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_GetProfileResponse["errorcode"] = "" 
                l_GetProfileResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_GetProfileResponse["status"] = "FAILED"
            l_GetProfileResponse["message"] = str(e)
            l_GetProfileResponse["errorcode"] = ""  
            l_GetProfileResponse["data"] = {"null"}

        return l_GetProfileResponse

    def GetOrderBook(self, f_OrderBookInfo):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetOrderBook request send")
        l_OrderBookResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "OrderBook")
            l_strGetdata = f_OrderBookInfo 

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetOrderBook request sent Successfully")
                l_OrderBookResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetOrderBook Request failed")

                l_OrderBookResponse["status"] = "FAILED"
                l_OrderBookResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_OrderBookResponse["errorcode"] = "" 
                l_OrderBookResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_OrderBookResponse["status"] = "FAILED"
            l_OrderBookResponse["message"] = str(e)
            l_OrderBookResponse["errorcode"] = ""  
            l_OrderBookResponse["data"] = {"null"}

        return l_OrderBookResponse

    def GetTradeBook(self, f_strclientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetTradeBook request send")
        l_TradeBookResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "TradeBook")
            l_strGetdata = {
                "clientcode": f_strclientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetTradeBook request sent Successfully")
                l_TradeBookResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetTradeBook Request failed")

                l_TradeBookResponse["status"] = "FAILED"
                l_TradeBookResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_TradeBookResponse["errorcode"] = "" 
                l_TradeBookResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_TradeBookResponse["status"] = "FAILED"
            l_TradeBookResponse["message"] = str(e)
            l_TradeBookResponse["errorcode"] = ""  
            l_TradeBookResponse["data"] = {"null"}

        return l_TradeBookResponse

    def GetPosition(self, f_strclientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetPosition request send")
        l_GetPositionResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "GetPosition")
            l_strGetdata = {
                "clientcode": f_strclientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetPosition request sent Successfully")
                l_GetPositionResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetPosition Request failed")

                l_GetPositionResponse["status"] = "FAILED"
                l_GetPositionResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_GetPositionResponse["errorcode"] = "" 
                l_GetPositionResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_GetPositionResponse["status"] = "FAILED"
            l_GetPositionResponse["message"] = str(e)
            l_GetPositionResponse["errorcode"] = ""  
            l_GetPositionResponse["data"] = {"null"}

        return l_GetPositionResponse

    def GetDPHolding(self, f_strclientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetDPHolding request send")
        l_DPHoldingResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "DPHolding")
            l_strGetdata = {
                "clientcode": f_strclientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetDPHolding request sent Successfully")
                l_DPHoldingResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetDPHolding Request failed")

                l_DPHoldingResponse["status"] = "FAILED"
                l_DPHoldingResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_DPHoldingResponse["errorcode"] = "" 
                l_DPHoldingResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_DPHoldingResponse["status"] = "FAILED"
            l_DPHoldingResponse["message"] = str(e)
            l_DPHoldingResponse["errorcode"] = ""  
            l_DPHoldingResponse["data"] = {"null"}

        return l_DPHoldingResponse

    def PlaceOrder(self, f_PlaceOrderInfo):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize PlaceOrder request send")
        l_PlaceOrderResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "PlaceOrder")
            l_strGetdata = f_PlaceOrderInfo 

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "PlaceOrder request sent Successfully")
                l_PlaceOrderResponse = l_strDICT
                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "PlaceOrder Request failed")

                l_PlaceOrderResponse["status"] = "FAILED"
                l_PlaceOrderResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_PlaceOrderResponse["errorcode"] = "" 
                l_PlaceOrderResponse["uniqueorderid"] = "" 


        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_PlaceOrderResponse["status"] = "FAILED"
            l_PlaceOrderResponse["message"] = str(e)
            l_PlaceOrderResponse["errorcode"] = ""  
            l_PlaceOrderResponse["uniqueorderid"] = "" 
        return l_PlaceOrderResponse


    def ModifyOrder(self, f_ModifyOrderInfo):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize ModifyOrder request send")
        l_ModifyOrderResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "ModifyOrder")
            l_strGetdata = f_ModifyOrderInfo 

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "ModifyOrder request sent Successfully")
                l_ModifyOrderResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "ModifyOrder Request failed")

                l_ModifyOrderResponse["status"] = "FAILED"
                l_ModifyOrderResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_ModifyOrderResponse["errorcode"] = "" 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_ModifyOrderResponse["status"] = "FAILED"
            l_ModifyOrderResponse["message"] = str(e)
            l_ModifyOrderResponse["errorcode"] = ""  

        return l_ModifyOrderResponse


    def CancelOrder(self, f_orderid, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize CancelOrder request send")
        l_CancelOrderResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "CancelOrder")
            l_strGetdata = {
                "clientcode" : f_clientcode,
                "uniqueorderid" : f_orderid
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "CancelOrder request sent Successfully")
                l_CancelOrderResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "CancelOrder Request failed")

                l_CancelOrderResponse["status"] = "FAILED"
                l_CancelOrderResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_CancelOrderResponse["errorcode"] = "" 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_CancelOrderResponse["status"] = "FAILED"
            l_CancelOrderResponse["message"] = str(e)
            l_CancelOrderResponse["errorcode"] = ""  

        return l_CancelOrderResponse


    def PositionConversion(self, f_PositionConversionInfo):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize PositionConversion request send")
        l_PositionConversionResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "positionconversion")
            l_strGetdata = f_PositionConversionInfo

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "PositionConversion request sent Successfully")
                l_PositionConversionResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "PositionConversion Request failed")

                l_PositionConversionResponse["status"] = "FAILED"
                l_PositionConversionResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_PositionConversionResponse["errorcode"] = ""                 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_PositionConversionResponse["status"] = "FAILED"
            l_PositionConversionResponse["message"] = str(e)
            l_PositionConversionResponse["errorcode"] = ""  

        return l_PositionConversionResponse

    def GetReportMargin(self, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetRMSSummary request send")
        l_RMSSummaryResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "marginreport")
            l_strGetdata = {
                "clientcode" : f_clientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetRMSSummary request sent Successfully")
                l_RMSSummaryResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetRMSSummary Request failed")

                l_RMSSummaryResponse["status"] = "FAILED"
                l_RMSSummaryResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_RMSSummaryResponse["errorcode"] = ""
                l_RMSSummaryResponse["data"] = {"null"} 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_RMSSummaryResponse["status"] = "FAILED"
            l_RMSSummaryResponse["message"] = str(e)
            l_RMSSummaryResponse["errorcode"] = ""
            l_RMSSummaryResponse["data"] = {"null"}    

        return l_RMSSummaryResponse

    def GetReportMarginSummary(self, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetRMSSummary request send")
        l_RMSSummaryResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "marginsummary")
            l_strGetdata = {
                "clientcode" : f_clientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetRMSSummary request sent Successfully")
                l_RMSSummaryResponse = l_strDICT
                            

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetRMSSummary Request failed")

                l_RMSSummaryResponse["status"] = "FAILED"
                l_RMSSummaryResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_RMSSummaryResponse["errorcode"] = ""
                l_RMSSummaryResponse["data"] = {"null"} 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_RMSSummaryResponse["status"] = "FAILED"
            l_RMSSummaryResponse["message"] = str(e)
            l_RMSSummaryResponse["errorcode"] = ""
            l_RMSSummaryResponse["data"] = {"null"}    

        return l_RMSSummaryResponse

    def GetReportMarginDetail(self, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetRMSDetail request send")
        l_RMSDetailResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "margindetail")
            l_strGetdata = {
                "clientcode" : f_clientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetRMSDetail request sent Successfully")
                l_RMSDetailResponse = l_strDICT

                            
            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetRMSDetail Request failed")

                l_RMSDetailResponse["status"] = "FAILED"
                l_RMSDetailResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_RMSDetailResponse["errorcode"] = ""
                l_RMSDetailResponse["data"] = {"null"} 

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_RMSDetailResponse["status"] = "FAILED"
            l_RMSDetailResponse["message"] = str(e)
            l_RMSDetailResponse["errorcode"] = ""
            l_RMSDetailResponse["data"] = {"null"}    

        return l_RMSDetailResponse



    def GetLtp(self, f_LTPData):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetLtp request send")
        l_LTPDataResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "ltadata")
            l_strGetdata = f_LTPData

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetLtp request sent Successfully")
                l_LTPDataResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetLtp Request failed")

                l_LTPDataResponse["status"] = "FAILED"
                l_LTPDataResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_LTPDataResponse["errorcode"] = "" 
                l_LTPDataResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_LTPDataResponse["status"] = "FAILED"
            l_LTPDataResponse["message"] = str(e)
            l_LTPDataResponse["errorcode"] = ""
            l_LTPDataResponse["data"] = {"null"}  

        return l_LTPDataResponse



    def GetInstrumentFile(self, f_exchangename, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetInstrumentFile request send")
        l_ExchangeDataResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "exchangedata")
            l_strGetdata = {
                "clientcode" : f_clientcode,
                "exchangename" : f_exchangename
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetInstrumentFile request sent Successfully")
                l_ExchangeDataResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetInstrumentFile Request failed")

                l_ExchangeDataResponse["status"] = "FAILED"
                l_ExchangeDataResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_ExchangeDataResponse["errorcode"] = "" 
                l_ExchangeDataResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_ExchangeDataResponse["status"] = "FAILED"
            l_ExchangeDataResponse["message"] = str(e)
            l_ExchangeDataResponse["errorcode"] = ""
            l_ExchangeDataResponse["data"] = {"null"}  

        return l_ExchangeDataResponse


    def GetOrderDetailByUniqueorderID(self, f_orderid, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetOrderDetailByUniqueorderID request send")
        l_OrderDetailResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "getorderdetailbyunqueorderid")
            l_strGetdata = {
                "clientcode" : f_clientcode,
                "uniqueorderid" : f_orderid
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetOrderDetailByUniqueorderID request sent Successfully")
                l_OrderDetailResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetOrderDetailByUniqueorderID Request failed")

                l_OrderDetailResponse["status"] = "FAILED"
                l_OrderDetailResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_OrderDetailResponse["errorcode"] = "" 
                l_OrderDetailResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_OrderDetailResponse["status"] = "FAILED"
            l_OrderDetailResponse["message"] = str(e)
            l_OrderDetailResponse["errorcode"] = ""
            l_OrderDetailResponse["data"] = {"null"}  

        return l_OrderDetailResponse


    def GetTradeDetailByUniqueorderID(self, f_orderid, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetTradeDetailByUniqueorderID request send")
        l_TradeDetailResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "gettradedetailbyuniqueorderid")
            l_strGetdata = {
                "clientcode" : f_clientcode,
                "uniqueorderid" : f_orderid
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetTradeDetailByUniqueorderID request sent Successfully")
                l_TradeDetailResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetTradeDetailByUniqueorderID Request failed")

                l_TradeDetailResponse["status"] = "FAILED"
                l_TradeDetailResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_TradeDetailResponse["errorcode"] = "" 
                l_TradeDetailResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_TradeDetailResponse["status"] = "FAILED"
            l_TradeDetailResponse["message"] = str(e)
            l_TradeDetailResponse["errorcode"] = ""
            l_TradeDetailResponse["data"] = {"null"}  

        return l_TradeDetailResponse

    def GetBrokerageDetail(self, f_BrokerageDetailInfo):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize GetBrokerageDetail request send")
        l_BrokerageDetailResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "getbrokeragedetail")
            l_strGetdata = f_BrokerageDetailInfo

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "GetBrokerageDetail request sent Successfully")
                l_BrokerageDetailResponse = l_strDICT

                             
            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "GetBrokerageDetail Request failed")

                l_BrokerageDetailResponse["status"] = "FAILED"
                l_BrokerageDetailResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_BrokerageDetailResponse["errorcode"] = "" 
                l_BrokerageDetailResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_BrokerageDetailResponse["status"] = "FAILED"
            l_BrokerageDetailResponse["message"] = str(e)
            l_BrokerageDetailResponse["errorcode"] = ""
            l_BrokerageDetailResponse["data"] = {"null"}  

        return l_BrokerageDetailResponse

    # Internally Called API
    def getbroadcastmaxlimit(self, f_clientcode = None):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize getbroadcastmaxlimit request send")
        l_GetBroadcastMaxLimitResponse  = {}

        try:
            l_strApiUrl = MOFSLOPENAPI.GetUrl(self, "getbroadcastmaxlimit")
            l_strGetdata = {
                "clientcode" : f_clientcode
            }

            l_strJSON = MOFSLOPENAPI.validate(self, l_strApiUrl, l_strGetdata)
            if "GET ERROR " not in l_strJSON:
                l_strDICT = json.loads(l_strJSON)    
                WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "getbroadcastmaxlimit request sent Successfully")
                l_GetBroadcastMaxLimitResponse = l_strDICT

                             

            else:
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
                WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "getbroadcastmaxlimit Request failed")

                l_GetBroadcastMaxLimitResponse["status"] = "FAILED"
                l_GetBroadcastMaxLimitResponse["message"] = l_strJSON.replace("GET ERROR ", "")
                l_GetBroadcastMaxLimitResponse["errorcode"] = "" 
                l_GetBroadcastMaxLimitResponse["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_GetBroadcastMaxLimitResponse["status"] = "FAILED"
            l_GetBroadcastMaxLimitResponse["message"] = str(e)
            l_GetBroadcastMaxLimitResponse["errorcode"] = ""
            l_GetBroadcastMaxLimitResponse["data"] = {"null"}  

        return l_GetBroadcastMaxLimitResponse

    def TradeWebhook(self, f_userid):

        WriteIntoLog("SUCCESS", "MOFSLOPENAPI.py", "Initilaize TradeWebhook request send")
        l_TradeWebhook  = {}

        try:
            l_strURL = self.m_Base_Url + "/webhook"  # "https://uatopenapi.motilaloswal.com/webhook"
            # l_strURL = "http://192.168.34.220:8080/webhook"
            l_strGetdata = {
                "clientid" : f_userid,
                "authtoken": self.m_strMOFSLToken,
                "apikey": self.m_strApikey
            }
            l_strJSON = requests.request(method = 'get', url =l_strURL , data =json.dumps(l_strGetdata))

            # l_strDICT = json.loads(l_strJSON)
            l_TradeWebhook = l_strJSON.json()
            # print(data, type(data))        

            # else:
            #     WriteIntoLog("FAILED", "MOFSLOPENAPI.py", l_strJSON.replace("GET ERROR ", ""))
            #     WriteIntoLog("FAILED", "MOFSLOPENAPI.py", "TradeWebhook Request failed")

            #     l_TradeWebhook["status"] = "FAILED"
            #     l_TradeWebhook["message"] = l_strJSON.replace("GET ERROR ", "")
            #     l_TradeWebhook["errorcode"] = "" 
            #     l_TradeWebhook["data"] = {"null"}

        except Exception as e:

            WriteIntoLog("FAILED", "MOFSLOPENAPI.py", str(e)) 

            l_TradeWebhook["status"] = "FAILED"
            l_TradeWebhook["message"] = str(e)
            l_TradeWebhook["errorcode"] = ""
            l_TradeWebhook["data"] = {"null"}  

        return l_TradeWebhook


# --------------------------------------------------------------------------------------------------------
# -----------------------------------------------Websocket------------------------------------------------
# --------------------------------------------------------------------------------------------------------



    def Login_on_open(self):

        msg_type = ("Q".encode())
        clientcode = self.m_clientcode
        Websocket_version = self.Websocket_version
        clientcode_buffer1 = (clientcode.ljust(15," ")).encode()
        clientcode_buffer2 = (clientcode.ljust(30," ")).encode()
        version_buffer = (Websocket_version.ljust(10," ")).encode()
        padding = (" " * 45).encode()
        LoginPacket = pack("=cHB15sB30sBBBB10sBBBBB45s", msg_type, 111, len(clientcode), clientcode_buffer1,
        len(clientcode), clientcode_buffer2, 1, 1, 1, len(Websocket_version), version_buffer, 0, 0, 0, 0, 1, padding)
        # print(LoginPacket)
        self.ws1.send(LoginPacket)
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Login Packet Sent")
        # print("Login Packet sent")

    def ReLogin_on_error(self):

        msg_type = ("q".encode())
        clientcode = self.m_clientcode
        Websocket_version = self.Websocket_version
        clientcode_buffer1 = (clientcode.ljust(15," ")).encode()
        clientcode_buffer2 = (clientcode.ljust(30," ")).encode()
        version_buffer = (Websocket_version.ljust(10," ")).encode()
        padding = (" " * 45).encode()
        ReLoginPacket = pack("=cHB15sB30sBBBB10sBBBBB45s", msg_type, 111, len(clientcode), clientcode_buffer1,
        len(clientcode), clientcode_buffer2, 1, 1, 1, len(Websocket_version), version_buffer, 0, 0, 0, 0, 1, padding)
        # print(LoginPacket)
        self.ws1.send(ReLoginPacket)
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "ReLogin Packet was Sent after connection lost")
        # print("ReConnection Packet sent")

    def Register(self, f_exchange, f_exchangetype, f_scriptcode):
        self.m_scriptask = "D"

        l_MaxBroadcastLimit = self.m_MaxBroadcastLimit
        # try:
        #     l_DICT_MaxBroadcastLimit = self.getbroadcastmaxlimit(self.m_clientcodeDealer)
        #     l_MaxBroadcastLimit = l_DICT_MaxBroadcastLimit["data"]["MaxBroadcastLimit"]
        # except Exception as e:
        #     WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", str(e))
        #     l_MaxBroadcastLimit = 0
       

        if l_MaxBroadcastLimit == 0 :
            MaxBroadcastLimit = 200
        else :
            MaxBroadcastLimit = l_MaxBroadcastLimit

        if (len(self.l_scrip_code) < MaxBroadcastLimit):

            if f_scriptcode not in self.l_scrip_code:
                self.l_scrip_code.append(f_scriptcode)

            l_exchange = f_exchange.upper()
            if (l_exchange== "NSECD"):
                l_exchangeindex = "C"
            elif (l_exchange == "NCDEX"):
                l_exchangeindex = "D"
            elif (l_exchange == "BSEFO"):
                l_exchangeindex = "G"
            else :
                l_exchangeindex = l_exchange[0]

            l_exchangetype = f_exchangetype.upper()
            l_exchangetypeindex = l_exchangetype[0]
            if self.m_strMOFSLToken:
                msg_type = ("D".encode())
                exchange = (l_exchangeindex.encode())
                exchangetype = (l_exchangetypeindex.encode())
                script = f_scriptcode
                AddToList = 1
                
                RegisterPacket = pack("=cHcciB", msg_type, 7, exchange, exchangetype, script, AddToList)
                self.Login_on_open()
                self.ws1.send(RegisterPacket)
                Log_Message = ("Script %d Register Packet Sent"%(f_scriptcode))
                WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
                # print(RegisterPacket)
                # print("Register Packet sent")
            else:
                print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

        else :
            print("Scrip count is greater than max limit")
            Log_Message = ("Script %d Register Failed, Scrip count is greater than max limit"%(f_scriptcode))
            WriteIntoLog_Broadcast("Info", "MOFSLOPENAPI.py", Log_Message)

    def UnRegister(self, f_exchange, f_exchangetype, f_scriptcode):
        self.m_scriptask = "D"
        self.l_scrip_code.remove(f_scriptcode)

        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
                l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        l_exchangetype = f_exchangetype.upper()
        l_exchangetypeindex = l_exchangetype[0]
        if self.m_strMOFSLToken:
            msg_type = ("D".encode())
            exchange = (l_exchangeindex.encode())
            exchangetype = (l_exchangetypeindex.encode())
            script = f_scriptcode
            AddToList = 0

            UnRegisterPacket = pack("=cHcciB", msg_type, 7, exchange, exchangetype, script, AddToList)
            # print(UnRegisterPacket)
            self.Login_on_open()
            self.ws1.send(UnRegisterPacket)
            Log_Message = ("Script %d UnRegister Packet Sent"%(f_scriptcode))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # print("UnRegister Packet sent")
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

    def IndexRegister(self, f_exchange):
        self.m_indextask = "H" 
        
        # l_exchange = f_exchange.upper()
        # l_exchangeindex = l_exchange[0]
        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
            l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        self.l_exchange_index.append(l_exchangeindex)
        
        if self.m_strMOFSLToken:
            self.Login_on_open()
            Log_Message = ("Index %s Register Packet Sent"%(f_exchange))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # print("IndexRegister Packet sent")
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

    def IndexUnregister(self, f_exchange):
        self.m_indextask = "H"

        # l_exchange = f_exchange.upper()
        # l_exchangeindex = l_exchange[0]
        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
            l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        self.l_exchange_index.remove(l_exchangeindex)
        # print("IndexUnregister Packet sent")
        if self.m_strMOFSLToken:
            Log_Message = ("Index %s UnRegister Packet Sent"%(f_exchange))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # self.Login_on_open()
            pass
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})


    def Packet_Condition(self, message):
        # time.sleep(1)
        msg = message
        if len(msg) % self.m_responsepacketlength == 0:
            self.Packet_Parsing(message)

        else:
            # q_msg = Queue()
            for i in msg:
                self.q_msg.put(i)
                if len(self.q_msg) == 30:
                        self.Packet_Parsing(self.q_msg)
                        self.q_msg.get(self.q_msg[0:30]) 


    def Packet_Parsing(self, message):
        # time.sleep(1)
        msg = message
        # self._Broadcast_on_message(self.ws1,message_type,msg)
        # print(msg)
        # print(len(msg), type(msg))

        if len(msg) % self.m_responsepacketlength == 0:
        
            l_Response30bytes=[]
            l_headerdecodedlist=[]
            l_msglist=[]
            for i in range(0, len(msg), self.m_responsepacketlength):
                l_Response30bytes.append(msg[i:i+ self.m_responsepacketlength])
                l_30bytessplitlist = l_Response30bytes
            

            for i in l_30bytessplitlist:
                b_exchange, b_scrip, b_time, b_msgtype = i[:1], i[1:5], i[5:9], i[9:10]
                b_20bytesbody = i[10:30]

                exchange = b_exchange.decode()
                scrip = int.from_bytes(b_scrip, byteorder= "little", signed=True)
                epoch1 = int.from_bytes(b_time, byteorder= "little", signed=True)
                epoch2 = datetime(1980, 1, 1, 0, 0, 0).timestamp()
                t = epoch1 + epoch2
                my_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))

                msgtype = b_msgtype.decode()
                
                l_headerdecodedlist.append(exchange)
                l_headerdecodedlist.append(scrip)
                l_headerdecodedlist.append(my_time)
                l_headerdecodedlist.append(msgtype)

                l_headerdecodedlist.append(b_20bytesbody)
            # print(l_headerdecodedlist)
            # print(len(l_headerdecodedlist), type(l_headerdecodedlist))
                    
            l_msglist = [l_headerdecodedlist[i:i+5] for i in range(0, len(l_headerdecodedlist), 5)]
            # print(l_msglist)
            # print(len(l_msglist), type(l_msglist)) 



            if self.m_scriptask == "D":
                for i in l_msglist:

                    l_msg = i
                    msg_type = i[3]
                    l_scripcode = i[1]
                    if (l_scripcode in self.l_scrip_code):
                        if msg_type == "A":
                            self.LTP(l_msg)
                        elif (msg_type =="B" or msg_type =="C" or msg_type =="D"or msg_type =="E" or msg_type =="F"):
                            self.MarketDepth(l_msg)
                        elif msg_type == "G":
                            self.DayOHLC(l_msg)
                        elif msg_type == "W":
                            self.DPR(l_msg)
                        elif msg_type == "m":
                            self.OpenInterest(l_msg)
                        elif  msg_type == "1":
                            # Log_Message = ("Heartbeat request %s received"%(l_msg))
                            # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                            self.Heartbeat(l_msg)
                        else:
                            # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                            pass
            else:
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    
                    if msg_type == "1":
                        # Log_Message_1 = ("Heartbeat request %s received"%(l_msg))
                        # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                        self.Heartbeat(l_msg)
                    else:
                        # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                        pass      
            
            if self.m_indextask == "H":
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    l_exchange = i[0]
                    if (l_exchange in self.l_exchange_index):
                        if msg_type == "H":
                            self.Index(l_msg)
                        elif  msg_type == "1":
                            # Log_Message_2 = ("Heartbeat request %s received"%(l_msg))
                            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                            self.Heartbeat(l_msg)
                        # elif msg_type == "G":
                        #     self.DayOHLC(l_msg)
                        else:
                            # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                            pass
            else:
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    
                    if msg_type == "1":
                        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                        self.Heartbeat(l_msg)
                    else:
                        # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                        pass                        
        else:
            l_message_type = "NotSpecified"
            self._Broadcast_on_message(self.ws1,l_message_type,msg)
            # print(msg)
            # print(len(msg), type(msg))


    def LTP(self, f_msg):
        l_LTPResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]
        b_Rate, b_Qty, b_Cumulative_Qty, b_AvgTradePrice, b_Open_Interest = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:16], l_msg[4][16:]

        flt_1 = unpack("f", b_Rate)
        l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
        l_Rate = round(l_Rateflt, 2)

        l_Qty = int.from_bytes(b_Qty, byteorder= "little", signed=True)
        l_Cumulative_Qty = int.from_bytes(b_Cumulative_Qty, byteorder= "little", signed=True)

        flt_2 = unpack("f", b_AvgTradePrice)
        l_AvgTradePriceflt = float('.'.join(str(elem) for elem in flt_2))
        l_AvgTradePrice = round(l_AvgTradePriceflt, 2)

        l_Open_Interest = int.from_bytes(b_Open_Interest, byteorder= "little", signed=True)

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_LTPResponseData["Exchange"] = "NSE"
            else :
                l_LTPResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_LTPResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_LTPResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_LTPResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_LTPResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_LTPResponseData["Exchange"] = "BSEFO"

              
        # l_LTPResponseData["Exchange"] = l_exchange
        l_LTPResponseData["Scrip Code"] = l_scrip
        l_LTPResponseData["Time"] = l_time
        # l_LTPResponseData["Type"] = "LTP"                 #l_msgtype

        l_LTPResponseData["LTP_Rate"] = l_Rate
        l_LTPResponseData["LTP_Qty"] = l_Qty
        l_LTPResponseData["LTP_Cumulative Qty"] = l_Cumulative_Qty
        l_LTPResponseData["LTP_AvgTradePrice"] = l_AvgTradePrice
        l_LTPResponseData["LTP_Open Interest"] = l_Open_Interest

        self._Broadcast_on_message(self.ws1,"LTP",l_LTPResponseData)


    def MarketDepth(self, f_msg):
        l_MarketDepthResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_BidRate,b_BidQty, b_BidOrder, b_OfferRate, b_OfferQty, b_OfferOrder  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:10], l_msg[4][10:14], l_msg[4][14:18], l_msg[4][18:]
        
        flt_1 = unpack("f", b_BidRate)
        l_BidRateflt = float('.'.join(str(elem) for elem in flt_1))
        l_BidRate = round(l_BidRateflt, 2)

        l_BidQty = int.from_bytes(b_BidQty, byteorder= "little", signed=True)
        l_BidOrderflt = int.from_bytes(b_BidOrder, byteorder= "little", signed=True)
        l_BidOrder = round(l_BidOrderflt, 2)

        flt_2 = unpack("f", b_OfferRate)
        l_OfferRateflt = float('.'.join(str(elem) for elem in flt_2))
        l_OfferRate = round(l_OfferRateflt, 2)

        l_OfferQty = int.from_bytes(b_OfferQty, byteorder= "little", signed=True)
        l_OfferOrderflt = int.from_bytes(b_OfferOrder, byteorder= "little", signed=True)   
        l_OfferOrder = round(l_OfferOrderflt, 2)     
        
        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_MarketDepthResponseData["Exchange"] = "NSE"
            else :
                l_MarketDepthResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_MarketDepthResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_MarketDepthResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_MarketDepthResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_MarketDepthResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_MarketDepthResponseData["Exchange"] = "BSEFO"


        # l_MarketDepthResponseData["Exchange"] = l_exchange
        l_MarketDepthResponseData["Scrip Code"] = l_scrip
        l_MarketDepthResponseData["Time"] = l_time
        # l_MarketDepthResponseData["Type"] = "MarketDepth"               #l_msgtype

        l_MarketDepthResponseData["BidRate"] = l_BidRate
        l_MarketDepthResponseData["BidQty"] = l_BidQty
        l_MarketDepthResponseData["BidOrder"] = l_BidOrder
        l_MarketDepthResponseData["OfferRate"] = l_OfferRate
        l_MarketDepthResponseData["OfferQty"]= l_OfferQty
        l_MarketDepthResponseData["OfferOrder"] = l_OfferOrder
        if l_msgtype == "B":
            l_MarketDepthResponseData["Level"] = 1
        elif l_msgtype == "C":
            l_MarketDepthResponseData["Level"] = 2
        elif l_msgtype == "D":
            l_MarketDepthResponseData["Level"] = 3
        elif l_msgtype == "E":
            l_MarketDepthResponseData["Level"] = 4
        elif l_msgtype == "F":
            l_MarketDepthResponseData["Level"] = 5
        else:
            pass

        self._Broadcast_on_message(self.ws1,"MarketDepth",l_MarketDepthResponseData)

    def DayOHLC(self, f_msg):
        l_DayOHLCResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_Open, b_High, b_Low, b_PrevDayClose, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:16], l_msg[4][16:]

        flt_1 = unpack("f", b_Open)
        l_Openflt = float('.'.join(str(elem) for elem in flt_1))
        l_Open = round(l_Openflt, 2)

        flt_2 = unpack("f", b_High)
        l_Highflt = float('.'.join(str(elem) for elem in flt_2))
        l_High = round(l_Highflt, 2)

        flt_3 = unpack("f", b_Low)
        l_Lowflt = float('.'.join(str(elem) for elem in flt_3))
        l_Low = round(l_Lowflt, 2)

        flt_4 = unpack("f", b_PrevDayClose)
        l_PrevDayCloseflt = float('.'.join(str(elem) for elem in flt_4))
        l_PrevDayClose = round(l_PrevDayCloseflt, 2)

        # l_Reserved = b_Reserved.decode()    

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_DayOHLCResponseData["Exchange"] = "NSE"
            else :
                l_DayOHLCResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_DayOHLCResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_DayOHLCResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_DayOHLCResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_DayOHLCResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_DayOHLCResponseData["Exchange"] = "BSEFO"

        # l_DayOHLCResponseData["Exchange"] = l_exchange
        l_DayOHLCResponseData["Scrip Code"] = l_scrip
        l_DayOHLCResponseData["Time"] = l_time
        # l_DayOHLCResponseData["Type"] = "DayOHLC"      #l_msgtype

        l_DayOHLCResponseData["Open"] = l_Open
        l_DayOHLCResponseData["High"] = l_High
        l_DayOHLCResponseData["Low"] = l_Low
        l_DayOHLCResponseData["PrevDayClose"] = l_PrevDayClose
        # l_DayOHLCResponseData["Reserved"]= l_Reserved

        self._Broadcast_on_message(self.ws1,"DayOHLC",l_DayOHLCResponseData)
    

    def DPR(self, f_msg):
        l_DPRResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_UpperCktLimit, b_LowerCktLimit, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:]

        flt_1 = unpack("f", b_UpperCktLimit)
        l_UpperCktLimitflt = float('.'.join(str(elem) for elem in flt_1))
        l_UpperCktLimit = round(l_UpperCktLimitflt, 2)

        flt_2 = unpack("f", b_LowerCktLimit)
        l_LowerCktLimitflt = float('.'.join(str(elem) for elem in flt_2))
        l_LowerCktLimit = round(l_LowerCktLimitflt, 2)

        # l_Reserved = b_Reserved.decode()

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_DPRResponseData["Exchange"] = "NSE"
            else :
                l_DPRResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_DPRResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_DPRResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_DPRResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_DPRResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_DPRResponseData["Exchange"] = "BSEFO"

        # l_DPRResponseData["Exchange"] = l_exchange
        l_DPRResponseData["Scrip Code"] = l_scrip
        l_DPRResponseData["Time"] = l_time
        # l_DPRResponseData["Type"] = "DPR"      #l_msgtype

        l_DPRResponseData["UpperCktLimit"] = l_UpperCktLimit
        l_DPRResponseData["LowerCktLimit"] = l_LowerCktLimit
        # l_DPRResponseData["Reserved"] = l_Reserved

        self._Broadcast_on_message(self.ws1,"DPR",l_DPRResponseData)


    def Heartbeat(self, f_msg):
        # print("Heartbeat Request Packet Received")
        msg_type = ("1".encode())
        HeartbeatPacket = pack("=cH", msg_type, 0)
        # print(HeartbeatPacket)
        self.ws1.send(HeartbeatPacket)
        Log_Message = ("Heartbeat response packet  %s sent"%(HeartbeatPacket))
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
        # print("Heartbeat Response Packet sent")

    def Index(self, f_msg):
        # print("Index H Packet")
        l_IndexResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_Rate, b_Reserved  = l_msg[4][:4], l_msg[4][4:]

        flt_1 = unpack("f", b_Rate)
        l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
        l_Rate = round(l_Rateflt, 2)

        # l_Reserved = b_Reserved.decode()

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_IndexResponseData["Exchange"] = "NSE"
            else :
                l_IndexResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_IndexResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_IndexResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_IndexResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_IndexResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_IndexResponseData["Exchange"] = "BSEFO" 

        # l_IndexResponseData["Exchange"] = l_exchange
        l_IndexResponseData["Scrip Code"] = l_scrip
        l_IndexResponseData["Time"] = l_time
        # l_IndexResponseData["Type"] = "Index" #l_msgtype

        l_IndexResponseData["Rate"] = l_Rate
        # l_IndexResponseData["Reserved"] = l_Reserved

        # print("Index H Packetafter")
        self._Broadcast_on_message(self.ws1,"Index",l_IndexResponseData)

    def OpenInterest(self, f_msg):
            l_OpenInterestResponseData = {}
            l_msg = f_msg
            l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

            b_OpenInterest, b_OpenInterestHigh, b_OpenInterestLow, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:]
            # flt_1 = unpack("f", b_Rate)
            # l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
            # l_Rate = round(l_Rateflt, 2)

            l_OpenInterest = int.from_bytes(b_OpenInterest, byteorder= "little", signed=True)
            l_OpenInterestHigh = int.from_bytes(b_OpenInterestHigh, byteorder= "little", signed=True)
            l_OpenInterestLow = int.from_bytes(b_OpenInterestLow, byteorder= "little", signed=True)

            # l_Reserved = b_Reserved.decode()

            if l_exchange == "N":
                if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                    l_OpenInterestResponseData["Exchange"] = "NSE"
                else :
                    l_OpenInterestResponseData["Exchange"] = "NSEFO"
            elif l_exchange == "B":
                l_OpenInterestResponseData["Exchange"] = "BSE"
            elif l_exchange == "M":
                l_OpenInterestResponseData["Exchange"] = "MCX"
            elif l_exchange == "D":
                l_OpenInterestResponseData["Exchange"] = "NCDEX"
            elif l_exchange == "C":
                l_OpenInterestResponseData["Exchange"] = "NSECD"
            elif l_exchange == "G":
                l_OpenInterestResponseData["Exchange"] = "BSEFO"


            # l_OpenInterestResponseData["Exchange"] = l_exchange
            l_OpenInterestResponseData["Scrip Code"] = l_scrip
            l_OpenInterestResponseData["Time"] = l_time
            # l_OpenInterestResponseData["Type"] = "OpenInterest"  #l_msgtype

            l_OpenInterestResponseData["Open Interest"] = l_OpenInterest
            l_OpenInterestResponseData["Open Interest High"] = l_OpenInterestHigh
            l_OpenInterestResponseData["Open Interest Low"] = l_OpenInterestLow
            # l_OpenInterestResponseData["Reserved"] = l_Reserved

            self._Broadcast_on_message(self.ws1,"OpenInterest",l_OpenInterestResponseData)

    def Broadcast_Logout(self):
        self.ws1.close()
        self.Broadcast_Logout_flag = False
        self.BroadcastAutoRelogin_flag = False
        



    def Tradelogin(self):
        if self.m_strMOFSLToken:
            l_data = {
            "clientid": self.m_clientcode,
            "authtoken": self.m_strMOFSLToken,
            "apikey": self.m_strApikey
            }

            j_Data = json.dumps(l_data)
            self.ws2.send(j_Data)
            WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "Tradelogin Packet Sent")
            # print(j_Data)

        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})


    def TradeSubscribe(self):
        if self.m_strMOFSLToken:
            l_data = {
            "clientid" : self.m_clientcode,
            "action" : "TradeSubscribe"
            }

            j_data = json.dumps(l_data)
            self.ws2.send(j_data)
            WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TradeSubscribe Packet Sent")
            # print(j_data)
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

    def TradeUnsubscribe(self):
        l_data = {
            "clientid" : self.m_clientcode,
            "action" : "TradeUnsubscribe"
        }

        j_data = json.dumps(l_data)
        self.ws2.send(j_data)
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TradeUnSubscribe Packet Sent")

    def OrderSubscribe(self):
        if self.m_strMOFSLToken:
            l_data = {
            "clientid" : self.m_clientcode,
            "action" : "OrderSubscribe"
            }

            j_data = json.dumps(l_data)
            self.ws2.send(j_data)
            WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "OrderUnsubscribe Packet Sent")
            # print(j_data)
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})


    def OrderUnsubscribe(self):
        l_data = {
            "clientid" : self.m_clientcode,
            "action" : "OrderUnsubscribe"
        }

        j_data = json.dumps(l_data)
        self.ws2.send(j_data)
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "OrderUnsubscribe Packet Sent")

    def Tradelogout(self):
        l_data = {
            "clientid" : self.m_clientcode,
            "action" : "logout"
        }

        j_data = json.dumps(l_data)
        self.ws2.send(j_data)
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "Tradelogout Packet Sent")

    def TradeStatus_HeartBeat(self):
        l_data = {
            "clientid" : self.m_clientcode,
            "action" : "heartbeat"
        }

        j_data = json.dumps(l_data)
        self.ws2.send(j_data)
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TradeStatus_HeartBeat Packet Sent")
        


    def Websocket1_connect(self):
        # websocket.enableTrace(True)
        # self.ws1 = websocket.WebSocketApp("wss://ws1feed.motilaloswal.com:443",
        #                              on_open=self.__Broadcast_on_open, 
        #                              on_message=self.__Broadcast_on_message,                                                                           
        #                              on_error=self.__Broadcast_on_error,
        #                              on_close=self.__Broadcast_on_close)

        self.ws1 = websocket.WebSocketApp("wss://ws1feed.motilaloswal.com/jwebsocket/jwebsocket",
                                     on_open=self.__Broadcast_on_open, 
                                     on_message=self.__Broadcast_on_message,                                                                           
                                     on_error=self.__Broadcast_on_error,
                                     on_close=self.__Broadcast_on_close)
        
        self.ws1.run_forever()
    

    def Websocket2_connect(self):

        if self.m_Base_Url == "https://openapi.motilaloswaluat.com":
            l_TradeStatus_connect_URL = "wss://openapi.motilaloswaluat.com/ws"
        elif self.m_Base_Url == "https://openapi.motilaloswal.com":
            l_TradeStatus_connect_URL = "wss://openapi.motilaloswal.com/ws"
        else:
            WriteIntoLog_TradeStatus("FAILED", "MOFSLOPENAPI.py", "Error in Base_Url Websocket2_connect")
            print("Error in Base_Url")

        # websocket.enableTrace(True)
        self.ws2 = websocket.WebSocketApp(l_TradeStatus_connect_URL, 
                                     on_open=self.__TradeStatus_on_open,
                                     on_message=self.__TradeStatus_on_message,
                                     on_error=self.__TradeStatus_on_error, 
                                     on_close=self.__TradeStatus_on_close)
        
        self.ws2.run_forever()


    def Broadcast_connect(self):
        try:
            l_DICT_MaxBroadcastLimit = self.getbroadcastmaxlimit(self.m_clientcodeDealer)
            self.m_MaxBroadcastLimit = l_DICT_MaxBroadcastLimit["data"]["MaxBroadcastLimit"]
        except Exception as e:
            WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", str(e))
            self.m_MaxBroadcastLimit = 0

        t1 = Thread(target=self.Websocket1_connect)        
        # starting thread 1
        t1.start()
        

    def TradeStatus_connect(self):
        t2 = Thread(target=self.Websocket2_connect)
        # starting thread 2
        t2.start()



    def __Broadcast_on_open(self, ws1):

        if self.Broadcast_Logout_flag == False:
            pass

        else:
            
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Broadcast Connection Opened")
            self._Broadcast_on_open(ws1)

            if self.BroadcastAutoRelogin_flag:
                def AutoReloginTimer():
                    while not AutoReloginTimer.cancelled:
                        if self.BroadcastAutoRelogin_counter == 0:
                            # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Broadcast Connection Reloged Packet Sent")
                            self.Broadcast_connect()

                            
                        self.BroadcastAutoRelogin_counter = 0
                        time.sleep(30)

                AutoReloginTimer.cancelled = False
                t = Thread(target=AutoReloginTimer)
                t.start()

        
    def __Broadcast_on_message(self, ws1, message):
        
        # l_CurrentMsgTime = time.time()
        # l_TimeDiffLastMsg = l_CurrentMsgTime - self.m_LastMsgTime 
        # if (l_TimeDiffLastMsg > 60 and l_TimeDiffLastMsg < l_CurrentMsgTime):
        #     WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Relogin Packet Sent")
        #     self._Broadcast_on_open(ws1)
        # self.m_LastMsgTime = l_CurrentMsgTime

        self.BroadcastAutoRelogin_counter = 1

        self.Packet_Condition(message)
        # self.Packet_Parsing(message)
        # print(ResponseData)

    def __Broadcast_on_error(self, ws1, error):
        if ( "'NoneType'" in str(error) ):
            pass
        else :
            WriteIntoLog_Broadcast("ERROR", "MOFSLOPENAPI.py", str(error))
        # print(error)
        
        # self._Broadcast_on_error(ws1, error)
                    
        if ( "timed" in str(error) ) or ( "Connection is already closed" in str(error) ) or ( "Connection to remote host was lost" in str(error)):
            # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "_Broadcast_on_error logged")
            # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Relogin Packet Sent")
            self.Broadcast_connect()
            
                       
        else:
            # self._Broadcast_on_error(ws1, error)
            pass

    def __Broadcast_on_close(self, ws1, close_status_code, close_msg):
        
        self.BroadcastAutoRelogin_flag = False
        # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Broadcast Connection Closed")
        if self.Broadcast_Logout_flag == False:
            self._Broadcast_on_close(ws1, close_status_code, "Logged Out" )
        else:
            self._Broadcast_on_close(ws1, close_status_code, close_msg)

        

    def __TradeStatus_on_open(self, ws2):
        
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TradeStatus Connection Opened")
        self._TradeStatus_on_open(ws2)

        if self.TradeStatusHeartbeat_flag:
            def background_task():
                while not background_task.cancelled:
                    self.TradeStatus_HeartBeat()
                    time.sleep(30)

            background_task.cancelled = False
            t = Thread(target=background_task)
            t.start()
        # if TradeStatusHeartbeat_flag:
        #     background_task.cancelled = False 
        

    def __TradeStatus_on_message(self, ws2, message):
        j_TradeStatusResponse = message
        # print(type(j_TradeStatusResponse))
        # # TradeStatusResponse = j_TradeStatusResponse.content.decode('utf-8')
        # # if 
        # TradeStatusResponse = json.loads(j_TradeStatusResponse)
        self._TradeStatus_on_message(self.ws2,"TradeStatus",j_TradeStatusResponse)

    def __TradeStatus_on_error(self, ws2, error):
        print(error) 
        # self._TradeStatus_on_error(ws2, error)
                    
        if ( "timed" in str(error) ) or ( "Connection is already closed" in str(error) ) or ( "Connection to remote host was lost" in str(error)):
            self.TradeStatus_connect()
                       

    def __TradeStatus_on_close(self, ws2, close_status_code, close_msg):
        
        WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TradeStatus Connection Closed")
        self.TradeStatusHeartbeat_flag = False
        
        self._TradeStatus_on_close(ws2, close_status_code, close_msg)


    def _Broadcast_on_open(self, ws1):
        pass
    
    def _Broadcast_on_message(self, ws1, message_type, message):
        pass

    def _Broadcast_on_error(self, ws1, error):
        pass
    
    def _Broadcast_on_close(self, ws1, close_status_code, close_msg):
        pass


    def _TradeStatus_on_open(self, ws2):
        pass

    def _TradeStatus_on_message(self, ws2, message_type, message):
        pass

    def _TradeStatus_on_error(self, ws2):
        pass

    def _TradeStatus_on_close(self, ws2, message_type, message):
        pass


# --------------------------------------------------------------------------------------------------------
# -----------------------------------------------TCPSocket------------------------------------------------
# --------------------------------------------------------------------------------------------------------

    def TCPLogin_on_open(self):

        msg_type = ("Q".encode())
        clientcode = self.m_clientcode
        Websocket_version = self.Websocket_version
        clientcode_buffer1 = (clientcode.ljust(15," ")).encode()
        clientcode_buffer2 = (clientcode.ljust(30," ")).encode()
        version_buffer = (Websocket_version.ljust(10," ")).encode()
        padding = (" " * 45).encode()
        LoginPacket = pack("=cHB15sB30sBBBB10sBBBBB45s", msg_type, 111, len(clientcode), clientcode_buffer1,
        len(clientcode), clientcode_buffer2, 1, 1, 1, len(Websocket_version), version_buffer, 0, 0, 0, 0, 1, padding)
        # print(LoginPacket)
        self.s.send(LoginPacket)
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "TCPLogin Packet Sent")
        # print("Login Packet sent")

    def TCPReLogin_on_error(self):

        msg_type = ("q".encode())
        clientcode = self.m_clientcode
        Websocket_version = self.Websocket_version
        clientcode_buffer1 = (clientcode.ljust(15," ")).encode()
        clientcode_buffer2 = (clientcode.ljust(30," ")).encode()
        version_buffer = (Websocket_version.ljust(10," ")).encode()
        padding = (" " * 45).encode()
        ReLoginPacket = pack("=cHB15sB30sBBBB10sBBBBB45s", msg_type, 111, len(clientcode), clientcode_buffer1,
        len(clientcode), clientcode_buffer2, 1, 1, 1, len(Websocket_version), version_buffer, 0, 0, 0, 0, 1, padding)
        # print(LoginPacket)
        self.s.send(ReLoginPacket)
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "TCPReLogin Packet was Sent after connection lost")
        # print("ReConnection Packet sent")

    def TCPRegister(self, f_exchange, f_exchangetype, f_scriptcode):
        self.m_TCPscriptask = "D"

        l_MaxBroadcastLimit = self.m_MaxBroadcastLimit
        # try:
        #     l_DICT_MaxBroadcastLimit = self.getbroadcastmaxlimit(self.m_clientcodeDealer)
        #     l_MaxBroadcastLimit = l_DICT_MaxBroadcastLimit["data"]["MaxBroadcastLimit"]
        # except Exception as e:
        #     WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", str(e))
        #     l_MaxBroadcastLimit = 0
       

        if l_MaxBroadcastLimit == 0 :
            MaxBroadcastLimit = 200
        else :
            MaxBroadcastLimit = l_MaxBroadcastLimit

        if (len(self.l_TCPscrip_code) < MaxBroadcastLimit):

            if f_scriptcode not in self.l_TCPscrip_code:
                self.l_TCPscrip_code.append(f_scriptcode)

            l_exchange = f_exchange.upper()
            if (l_exchange== "NSECD"):
                l_exchangeindex = "C"
            elif (l_exchange == "NCDEX"):
                l_exchangeindex = "D"
            elif (l_exchange == "BSEFO"):
                l_exchangeindex = "G"
            else :
                l_exchangeindex = l_exchange[0]

            l_exchangetype = f_exchangetype.upper()
            l_exchangetypeindex = l_exchangetype[0]
            if self.m_strMOFSLToken:
                msg_type = ("D".encode())
                exchange = (l_exchangeindex.encode())
                exchangetype = (l_exchangetypeindex.encode())
                script = f_scriptcode
                AddToList = 1
                
                RegisterPacket = pack("=cHcciB", msg_type, 7, exchange, exchangetype, script, AddToList)
                self.TCPLogin_on_open()
                self.s.send(RegisterPacket)
                Log_Message = ("TCPScript %d Register Packet Sent"%(f_scriptcode))
                WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
                # print(RegisterPacket)
                # print("Register Packet sent")
            else:
                print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

        else :
            print("TCPScrip count is greater than max limit")
            Log_Message = ("Script %d Register Failed, Scrip count is greater than max limit"%(f_scriptcode))
            WriteIntoLog_Broadcast("Info", "MOFSLOPENAPI.py", Log_Message)
            
    def TCPUnRegister(self, f_exchange, f_exchangetype, f_scriptcode):
        self.m_scriptask = "D"
        self.l_TCPscrip_code.remove(f_scriptcode)

        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
            l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        l_exchangetype = f_exchangetype.upper()
        l_exchangetypeindex = l_exchangetype[0]
        if self.m_strMOFSLToken:
            msg_type = ("D".encode())
            exchange = (l_exchangeindex.encode())
            exchangetype = (l_exchangetypeindex.encode())
            script = f_scriptcode
            AddToList = 0

            UnRegisterPacket = pack("=cHcciB", msg_type, 7, exchange, exchangetype, script, AddToList)
            # print(UnRegisterPacket)
            self.TCPLogin_on_open()
            self.s.send(UnRegisterPacket)
            Log_Message = ("TCPScript %d UnRegister Packet Sent"%(f_scriptcode))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # print("UnRegister Packet sent")
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})
  
    def TCPIndexRegister(self, f_exchange):
        self.m_TCPindextask = "H" 
        
        # l_exchange = f_exchange.upper()
        # l_exchangeindex = l_exchange[0]
        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
            l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        self.l_TCPexchange_index.append(l_exchangeindex)
        
        if self.m_strMOFSLToken:
            self.TCPLogin_on_open()
            Log_Message = ("TCPIndex %s Register Packet Sent"%(f_exchange))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # print("IndexRegister Packet sent")
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

    def TCPIndexUnregister(self, f_exchange):
        self.m_TCPindextask = "H"

        # l_exchange = f_exchange.upper()
        # l_exchangeindex = l_exchange[0]
        l_exchange = f_exchange.upper()
        if (l_exchange== "NSECD"):
            l_exchangeindex = "C"
        elif (l_exchange == "NCDEX"):
            l_exchangeindex = "D"
        elif (l_exchange == "BSEFO"):
            l_exchangeindex = "G"
        else :
            l_exchangeindex = l_exchange[0]

        self.l_TCPexchange_index.remove(l_exchangeindex)
        # print("IndexUnregister Packet sent")
        if self.m_strMOFSLToken:
            Log_Message = ("TCPIndex %s UnRegister Packet Sent"%(f_exchange))
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
            # self.Login_on_open()
            pass
        else:
            print({'status': 'ERROR', 'message': 'Authorization is InVaild In Header Parameter', 'errorcode': '', 'data': None})

    def TCPBroadcast_Logout(self):
        self.s.close()
        self.TCPBroadcast_Logout_flag = False
        self.TCPBroadcastAutoRelogin_flag = False

    def TCPPacket_Condition(self, message):
        # time.sleep(1)
        msg = message
        if len(msg) % self.m_TCPresponsepacketlength == 0:
            self.TCPPacket_Parsing(message)

        else:
            pass
            # print(len(msg))
            # try :
            #     # q_msg = Queue()
            #     for i in msg:
            #         self.q_msg.put(i)
            #         if self.q_msg.qsize() == 30:
            #                 self.Packet_Parsing(self.q_msg)
            #                 self.q_msg.get(q_msg[o:30]) 
            # except Exception as e: 
            #     print(e)

    def TCPPacket_Parsing(self, message):
        # time.sleep(1)
        msg = message
        # self._Broadcast_on_message(self.ws1,message_type,msg)
        # print(msg)
        # print(len(msg), type(msg))

        if len(msg) % self.m_TCPresponsepacketlength == 0:
        
            l_Response30bytes=[]
            l_headerdecodedlist=[]
            l_msglist=[]
            for i in range(0, len(msg), self.m_TCPresponsepacketlength):
                l_Response30bytes.append(msg[i:i+ self.m_TCPresponsepacketlength])
                l_30bytessplitlist = l_Response30bytes
            

            for i in l_30bytessplitlist:
                b_exchange, b_scrip, b_time, b_msgtype = i[:1], i[1:5], i[5:9], i[9:10]
                b_20bytesbody = i[10:30]

                exchange = b_exchange.decode()
                scrip = int.from_bytes(b_scrip, byteorder= "little", signed=True)
                epoch1 = int.from_bytes(b_time, byteorder= "little", signed=True)
                epoch2 = datetime(1980, 1, 1, 0, 0, 0).timestamp()
                t = epoch1 + epoch2
                my_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))

                msgtype = b_msgtype.decode()
                
                l_headerdecodedlist.append(exchange)
                l_headerdecodedlist.append(scrip)
                l_headerdecodedlist.append(my_time)
                l_headerdecodedlist.append(msgtype)

                l_headerdecodedlist.append(b_20bytesbody)
            # print(l_headerdecodedlist)
            # print(len(l_headerdecodedlist), type(l_headerdecodedlist))
                    
            l_msglist = [l_headerdecodedlist[i:i+5] for i in range(0, len(l_headerdecodedlist), 5)]
            # print(l_msglist)
            # print(len(l_msglist), type(l_msglist)) 



            if self.m_TCPscriptask == "D":
                for i in l_msglist:

                    l_msg = i
                    msg_type = i[3]
                    l_scripcode = i[1]
                    if (l_scripcode in self.l_TCPscrip_code):
                        if msg_type == "A":
                            self.TCPLTP(l_msg)
                        elif (msg_type =="B" or msg_type =="C" or msg_type =="D"or msg_type =="E" or msg_type =="F"):
                            self.TCPMarketDepth(l_msg)
                        elif msg_type == "G":
                            self.TCPDayOHLC(l_msg)
                        elif msg_type == "W":
                            self.TCPDPR(l_msg)
                        elif msg_type == "m":
                            self.TCPOpenInterest(l_msg)
                        elif  msg_type == "1":
                            # Log_Message = ("Heartbeat request %s received"%(l_msg))
                            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                            self.TCPHeartbeat(l_msg)
                        else:
                            # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                            pass
            else:
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    
                    if msg_type == "1":
                        # Log_Message_1 = ("Heartbeat request %s received"%(l_msg))
                        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                        self.TCPHeartbeat(l_msg)
                    else:
                        # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                        pass      
            
            if self.m_TCPindextask == "H":
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    l_exchange = i[0]
                    if (l_exchange in self.l_TCPexchange_index):
                        if msg_type == "H":
                            self.TCPIndex(l_msg)
                        elif  msg_type == "1":
                            # Log_Message_2 = ("Heartbeat request %s received"%(l_msg))
                            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                            self.TCPHeartbeat(l_msg)
                        # elif msg_type == "G":
                        #     self.DayOHLC(l_msg)
                        else:
                            # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                            pass
            else:
                for i in l_msglist:
                    l_msg = i
                    msg_type = i[3]
                    
                    if msg_type == "1":
                        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "Heartbeat request received")
                        self.TCPHeartbeat(l_msg)
                    else:
                        # self._Broadcast_on_message(self.ws1,msg_type,l_msg)
                        pass                        
        else:
            l_message_type = "NotSpecified"
            self._TCPBroadcast_on_message(l_message_type,msg)
            # print(msg)
            # print(len(msg), type(msg))

    def TCPLTP(self, f_msg):
        l_LTPResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]
        b_Rate, b_Qty, b_Cumulative_Qty, b_AvgTradePrice, b_Open_Interest = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:16], l_msg[4][16:]

        flt_1 = unpack("f", b_Rate)
        l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
        l_Rate = round(l_Rateflt, 2)

        l_Qty = int.from_bytes(b_Qty, byteorder= "little", signed=True)
        l_Cumulative_Qty = int.from_bytes(b_Cumulative_Qty, byteorder= "little", signed=True)

        flt_2 = unpack("f", b_AvgTradePrice)
        l_AvgTradePriceflt = float('.'.join(str(elem) for elem in flt_2))
        l_AvgTradePrice = round(l_AvgTradePriceflt, 2)

        l_Open_Interest = int.from_bytes(b_Open_Interest, byteorder= "little", signed=True)

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_LTPResponseData["Exchange"] = "NSE"
            else :
                l_LTPResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_LTPResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_LTPResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_LTPResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_LTPResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_LTPResponseData["Exchange"] = "BSEFO"

              
        # l_LTPResponseData["Exchange"] = l_exchange
        l_LTPResponseData["Scrip Code"] = l_scrip
        l_LTPResponseData["Time"] = l_time
        # l_LTPResponseData["Type"] = "LTP"                 #l_msgtype

        l_LTPResponseData["LTP_Rate"] = l_Rate
        l_LTPResponseData["LTP_Qty"] = l_Qty
        l_LTPResponseData["LTP_Cumulative Qty"] = l_Cumulative_Qty
        l_LTPResponseData["LTP_AvgTradePrice"] = l_AvgTradePrice
        l_LTPResponseData["LTP_Open Interest"] = l_Open_Interest

        self._TCPBroadcast_on_message("LTP",l_LTPResponseData)


    def TCPMarketDepth(self, f_msg):
        l_MarketDepthResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_BidRate,b_BidQty, b_BidOrder, b_OfferRate, b_OfferQty, b_OfferOrder  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:10], l_msg[4][10:14], l_msg[4][14:18], l_msg[4][18:]
        
        flt_1 = unpack("f", b_BidRate)
        l_BidRateflt = float('.'.join(str(elem) for elem in flt_1))
        l_BidRate = round(l_BidRateflt, 2)

        l_BidQty = int.from_bytes(b_BidQty, byteorder= "little", signed=True)
        l_BidOrderflt = int.from_bytes(b_BidOrder, byteorder= "little", signed=True)
        l_BidOrder = round(l_BidOrderflt, 2)

        flt_2 = unpack("f", b_OfferRate)
        l_OfferRateflt = float('.'.join(str(elem) for elem in flt_2))
        l_OfferRate = round(l_OfferRateflt, 2)

        l_OfferQty = int.from_bytes(b_OfferQty, byteorder= "little", signed=True)
        l_OfferOrderflt = int.from_bytes(b_OfferOrder, byteorder= "little", signed=True)   
        l_OfferOrder = round(l_OfferOrderflt, 2)     
        
        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_MarketDepthResponseData["Exchange"] = "NSE"
            else :
                l_MarketDepthResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_MarketDepthResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_MarketDepthResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_MarketDepthResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_MarketDepthResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_MarketDepthResponseData["Exchange"] = "BSEFO"


        # l_MarketDepthResponseData["Exchange"] = l_exchange
        l_MarketDepthResponseData["Scrip Code"] = l_scrip
        l_MarketDepthResponseData["Time"] = l_time
        # l_MarketDepthResponseData["Type"] = "MarketDepth"               #l_msgtype

        l_MarketDepthResponseData["BidRate"] = l_BidRate
        l_MarketDepthResponseData["BidQty"] = l_BidQty
        l_MarketDepthResponseData["BidOrder"] = l_BidOrder
        l_MarketDepthResponseData["OfferRate"] = l_OfferRate
        l_MarketDepthResponseData["OfferQty"]= l_OfferQty
        l_MarketDepthResponseData["OfferOrder"] = l_OfferOrder
        if l_msgtype == "B":
            l_MarketDepthResponseData["Level"] = 1
        elif l_msgtype == "C":
            l_MarketDepthResponseData["Level"] = 2
        elif l_msgtype == "D":
            l_MarketDepthResponseData["Level"] = 3
        elif l_msgtype == "E":
            l_MarketDepthResponseData["Level"] = 4
        elif l_msgtype == "F":
            l_MarketDepthResponseData["Level"] = 5
        else:
            pass

        self._TCPBroadcast_on_message("MarketDepth",l_MarketDepthResponseData)

    def TCPDayOHLC(self, f_msg):
        l_DayOHLCResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_Open, b_High, b_Low, b_PrevDayClose, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:16], l_msg[4][16:]

        flt_1 = unpack("f", b_Open)
        l_Openflt = float('.'.join(str(elem) for elem in flt_1))
        l_Open = round(l_Openflt, 2)

        flt_2 = unpack("f", b_High)
        l_Highflt = float('.'.join(str(elem) for elem in flt_2))
        l_High = round(l_Highflt, 2)

        flt_3 = unpack("f", b_Low)
        l_Lowflt = float('.'.join(str(elem) for elem in flt_3))
        l_Low = round(l_Lowflt, 2)

        flt_4 = unpack("f", b_PrevDayClose)
        l_PrevDayCloseflt = float('.'.join(str(elem) for elem in flt_4))
        l_PrevDayClose = round(l_PrevDayCloseflt, 2)

        # l_Reserved = b_Reserved.decode()    

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_DayOHLCResponseData["Exchange"] = "NSE"
            else :
                l_DayOHLCResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_DayOHLCResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_DayOHLCResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_DayOHLCResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_DayOHLCResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_DayOHLCResponseData["Exchange"] = "BSEFO"

        # l_DayOHLCResponseData["Exchange"] = l_exchange
        l_DayOHLCResponseData["Scrip Code"] = l_scrip
        l_DayOHLCResponseData["Time"] = l_time
        # l_DayOHLCResponseData["Type"] = "DayOHLC"      #l_msgtype

        l_DayOHLCResponseData["Open"] = l_Open
        l_DayOHLCResponseData["High"] = l_High
        l_DayOHLCResponseData["Low"] = l_Low
        l_DayOHLCResponseData["PrevDayClose"] = l_PrevDayClose
        # l_DayOHLCResponseData["Reserved"]= l_Reserved

        self._TCPBroadcast_on_message("DayOHLC",l_DayOHLCResponseData)
    

    def TCPDPR(self, f_msg):
        l_DPRResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_UpperCktLimit, b_LowerCktLimit, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:]

        flt_1 = unpack("f", b_UpperCktLimit)
        l_UpperCktLimitflt = float('.'.join(str(elem) for elem in flt_1))
        l_UpperCktLimit = round(l_UpperCktLimitflt, 2)

        flt_2 = unpack("f", b_LowerCktLimit)
        l_LowerCktLimitflt = float('.'.join(str(elem) for elem in flt_2))
        l_LowerCktLimit = round(l_LowerCktLimitflt, 2)

        # l_Reserved = b_Reserved.decode()

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_DPRResponseData["Exchange"] = "NSE"
            else :
                l_DPRResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_DPRResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_DPRResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_DPRResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_DPRResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_DPRResponseData["Exchange"] = "BSEFO"

        # l_DPRResponseData["Exchange"] = l_exchange
        l_DPRResponseData["Scrip Code"] = l_scrip
        l_DPRResponseData["Time"] = l_time
        # l_DPRResponseData["Type"] = "DPR"      #l_msgtype

        l_DPRResponseData["UpperCktLimit"] = l_UpperCktLimit
        l_DPRResponseData["LowerCktLimit"] = l_LowerCktLimit
        # l_DPRResponseData["Reserved"] = l_Reserved

        self._TCPBroadcast_on_message("DPR",l_DPRResponseData)


    def TCPHeartbeat(self, f_msg):
        # print("Heartbeat Request Packet Received")
        msg_type = ("1".encode())
        HeartbeatPacket = pack("=cH", msg_type, 0)
        # print(HeartbeatPacket)
        self.s.send(HeartbeatPacket)
        Log_Message = ("TCPHeartbeat response packet  %s sent"%(HeartbeatPacket))
        WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", Log_Message)
        # print("Heartbeat Response Packet sent")

    def TCPIndex(self, f_msg):
        # print("Index H Packet")
        l_IndexResponseData = {}
        l_msg = f_msg
        l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

        b_Rate, b_Reserved  = l_msg[4][:4], l_msg[4][4:]

        flt_1 = unpack("f", b_Rate)
        l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
        l_Rate = round(l_Rateflt, 2)

        # l_Reserved = b_Reserved.decode()

        if l_exchange == "N":
            if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                l_IndexResponseData["Exchange"] = "NSE"
            else :
                l_IndexResponseData["Exchange"] = "NSEFO"
        elif l_exchange == "B":
            l_IndexResponseData["Exchange"] = "BSE"
        elif l_exchange == "M":
            l_IndexResponseData["Exchange"] = "MCX"
        elif l_exchange == "D":
            l_IndexResponseData["Exchange"] = "NCDEX"
        elif l_exchange == "C":
            l_IndexResponseData["Exchange"] = "NSECD"
        elif l_exchange == "G":
            l_IndexResponseData["Exchange"] = "BSEFO" 

        # l_IndexResponseData["Exchange"] = l_exchange
        l_IndexResponseData["Scrip Code"] = l_scrip
        l_IndexResponseData["Time"] = l_time
        # l_IndexResponseData["Type"] = "Index" #l_msgtype

        l_IndexResponseData["Rate"] = l_Rate
        # l_IndexResponseData["Reserved"] = l_Reserved

        # print("Index H Packetafter")
        self._TCPBroadcast_on_message("Index",l_IndexResponseData)

    def TCPOpenInterest(self, f_msg):
        try :

            l_OpenInterestResponseData = {}
            l_msg = f_msg
            l_exchange, l_scrip, l_time, l_msgtype = l_msg[0], l_msg[1], l_msg[2], l_msg[3]

            b_OpenInterest, b_OpenInterestHigh, b_OpenInterestLow, b_Reserved  = l_msg[4][:4], l_msg[4][4:8], l_msg[4][8:12], l_msg[4][12:]
            # flt_1 = unpack("f", b_Rate)
            # l_Rateflt = float('.'.join(str(elem) for elem in flt_1))
            # l_Rate = round(l_Rateflt, 2)

            l_OpenInterest = int.from_bytes(b_OpenInterest, byteorder= "little", signed=True)
            l_OpenInterestHigh = int.from_bytes(b_OpenInterestHigh, byteorder= "little", signed=True)
            l_OpenInterestLow = int.from_bytes(b_OpenInterestLow, byteorder= "little", signed=True)

            # l_Reserved = b_Reserved.decode()

            if l_exchange == "N":
                if l_scrip <= 34999 or (l_scrip >= 888801 and l_scrip <= 888820):
                    l_OpenInterestResponseData["Exchange"] = "NSE"
                else :
                    l_OpenInterestResponseData["Exchange"] = "NSEFO"
            elif l_exchange == "B":
                l_OpenInterestResponseData["Exchange"] = "BSE"
            elif l_exchange == "M":
                l_OpenInterestResponseData["Exchange"] = "MCX"
            elif l_exchange == "D":
                l_OpenInterestResponseData["Exchange"] = "NCDEX"
            elif l_exchange == "C":
                l_OpenInterestResponseData["Exchange"] = "NSECD"
            elif l_exchange == "G":
                l_OpenInterestResponseData["Exchange"] = "BSEFO"


            # l_OpenInterestResponseData["Exchange"] = l_exchange
            l_OpenInterestResponseData["Scrip Code"] = l_scrip
            l_OpenInterestResponseData["Time"] = l_time
            # l_OpenInterestResponseData["Type"] = "OpenInterest"  #l_msgtype

            l_OpenInterestResponseData["Open Interest"] = l_OpenInterest
            l_OpenInterestResponseData["Open Interest High"] = l_OpenInterestHigh
            l_OpenInterestResponseData["Open Interest Low"] = l_OpenInterestLow
            # l_OpenInterestResponseData["Reserved"] = l_Reserved

            self._TCPBroadcast_on_message("OpenInterest",l_OpenInterestResponseData)
        except Exception as e :
            print(e)



    def TCPBroadcast_connect(self):
        # t1 = Thread(target=self.Websocket1_connect)        
        # # starting thread 1
        # t1.start()
        try:
            l_DICT_MaxBroadcastLimit = self.getbroadcastmaxlimit(self.m_clientcodeDealer)
            self.m_MaxBroadcastLimit = l_DICT_MaxBroadcastLimit["data"]["MaxBroadcastLimit"]
        except Exception as e:
            WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", str(e))
            self.m_MaxBroadcastLimit = 0
        
        if self.AttemptCountSocket <=5:
            # HOST = "127.0.0.1"  # The server's hostname or IP address
            HOST = "mofeed.motilaloswal.com"
            # PORT = 65432  # The port used by the server
            PORT = 18001

            try:
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.connect((HOST, PORT))
                WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TCPBroadcast_connect Connection Open") 

                self.__TCPBroadcast_on_open()
        
            except Exception as e:

                # print(e)
                WriteIntoLog_TradeStatus("FAILED", "MOFSLOPENAPI.py", "TCPBroadcast_connect Connection FAILED")
                WriteIntoLog_TradeStatus("SUCCESS", "MOFSLOPENAPI.py", "TCPBroadcast_connect Connection Retry")
                time.sleep(1)
                self.AttemptCountSocket += 1
                self.TCPBroadcast_connect()
                
        else :
            WriteIntoLog_TradeStatus("FAILED", "MOFSLOPENAPI.py", "TCPBroadcast_connect Connection FAILED Even after Retry")


    def __TCPBroadcast_on_open(self):

        if self.TCPBroadcast_Logout_flag == False:
            pass

        else:
            WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "TCPBroadcast Connection Opened")
            self._TCPBroadcast_on_open()

            if self.TCPBroadcastAutoRelogin_flag:
                def AutoReloginTimer():
                    while not AutoReloginTimer.cancelled:
                        if self.TCPBroadcastAutoRelogin_counter == 0:
                            # WriteIntoLog_Broadcast("SUCCESS", "MOFSLOPENAPI.py", "TCPBroadcast Connection Reloged Packet Sent")
                            self.TCPBroadcast_connect()

                            
                        self.TCPBroadcastAutoRelogin_counter = 0
                        time.sleep(30)

                AutoReloginTimer.cancelled = False
                t = Thread(target=AutoReloginTimer)
                t.start()

                self.__TCPBroadcast_on_message()

    def __TCPBroadcast_on_message(self):
        
        while True: 

            data = self.s.recv(102400)
            if not data :
                pass
            else:
                if len(data) >= 102400:
                    pass
                    # print(len(data))
                    # WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", "len(data)" +str(len(data)))
                elif len(data) < 30:
                    pass
                    # print(len(data))
                    # WriteIntoLog_Broadcast("FAILED", "MOFSLOPENAPI.py", "len(data)" +str(len(data)))
                else :
                    self.TCPBroadcastAutoRelogin_counter = 1
                    self.TCPPacket_Condition(data)
                    

    def _TCPBroadcast_on_open(self):
        pass

    def _TCPBroadcast_on_message(self, message_type, message):
        pass

        

        






