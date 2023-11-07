# Follow README.txt
# Install Packages 
# Run following command in terminal to install required packages :
# pip install -r requirements.txt

from MOFSLOPENAPI import MOFSLOPENAPI

# You will get Your api key from website 
ApiKey = "" 


# userid and password is your trading account username and password
userid = "" 
password = ""   
Two_FA = ""
vendorinfo = ""
clientcode = None 

# if Your SourceId is web then pass browsername and browser version in case of Desktop you dont need to passanyting

SourceID = "Desktop"            # Web,Desktop
browsername = "chrome"      
browserversion = "104"      
totp = ""
 
# NOTE:
# totp – Send the 6 digit OTP on login using any Authenticator App.
# OR pass it as blank and verify authtoken by verifyotp with otp received on phone or mail
# if otp expired use resendotp
 
# # Set Url for LIVE or UAT Testing
# # Enter Base Url for LIVE or UAT Testing 
# # 	1. For live 
# # 	   Base_Url = "https://openapi.motilaloswal.com"
# # 	2. For UAT
# # 	   Base_Url = "https://uatopenapi.motilaloswal.com"
Base_Url = "https://uatopenapi.motilaloswal.com"


# Initialize MofslOpenApi using Apikey, Base_Url and clientcode 
Mofsl = MOFSLOPENAPI(ApiKey, Base_Url, clientcode, SourceID, browsername, browserversion)

# Uncomment print statement to execute
# Loginrequest will always be first request with each following request

# Login by Clientcode and password
print("--------------------------------Login--------------------------------")
# Mofsl.login(userid, password)
print(Mofsl.login(userid, password, Two_FA, totp, vendorinfo))

# print("--------------------------------verifyotp--------------------------------")
# otp = input("Enter Input: ")
# print(Mofsl.verifyotp(otp))

# print("--------------------------------resendotp--------------------------------")
# print(Mofsl.resendotp())


# # GetProfile response for dealer
# print("--------------------------------GetProfile--------------------------------")
# # Mofsl.GetProfile(clientcode)  
# print(Mofsl.GetProfile(clientcode))


# # PlaceOrder
# print("--------------------------------PlaceOrder--------------------------------")
# # PlaceOrderInfo
# Orderinfo = {
#     "clientcode":clientcode,      
#     "exchange":"NSE",
#     "symboltoken":1660,
#     "buyorsell":"BUY",
#     "ordertype":"LIMIT",
#     "producttype":"Normal",
#     "orderduration":"GTD",
#     "price":235,
#     "triggerprice":0,
#     "quantityinlot":2,
#     "disclosedquantity":0,
#     "amoorder":"N",
#     "algoid":"",
#     "goodtilldate":"28-Feb-2022",
#     "tag":" "
# }

# # Mofsl.PlaceOrder(Orderinfo)
# print(Mofsl.PlaceOrder(Orderinfo))




# # ModifyOrder
# print("--------------------------------ModifyOrder--------------------------------")
# ModifiedOrderInfo = {
#     "clientcode":clientcode,
#     "uniqueorderid":"2600001T024312",
#     "newordertype":"LIMIT",
#     "neworderduration":"DAY",   
#     "newquantityinlot":100,
#     "newdisclosedquantity":0,
#     "newprice":235.50,
#     "newtriggerprice":0,
#     "newgoodtilldate": 0,
#     "lastmodifiedtime": "14-May-2022 11:31:25",
#     "qtytradedtoday": 0
# }

# # Mofsl.ModifyOrder(ModifiedOrderInfo)   
# print(Mofsl.ModifyOrder(ModifiedOrderInfo))


# # CancelOrder 
# print("--------------------------------CancelOrder--------------------------------")
# # orderid Will be recovered from orderbook
# # Mofsl.CancelOrder(orderid, clientcode)   
# print(Mofsl.CancelOrder("2600001T024312", clientcode))


# # GetOrderBook 
# print("--------------------------------GetOrderBook--------------------------------")
# OrderBookInfo = {
#     "clientcode":clientcode,
#     "dateandtime":""        #22-Dec-2022 15:16:02
# }
# # Mofsl.GetOrderBook(OrderBookInfo)   
# print(Mofsl.GetOrderBook(OrderBookInfo))


# # GetTradeBook 
# print("--------------------------------GetTradeBook--------------------------------")
# # Mofsl.GetTradeBook(clientcode)   
# print(Mofsl.GetTradeBook(clientcode))


# # GetPosition 
# print("--------------------------------GetPosition--------------------------------")
# # Mofsl.GetPosition(clientcode)   
# print(Mofsl.GetPosition(clientcode))


# # GetDPHolding 
# print("--------------------------------GetHolding--------------------------------")
# # Mofsl.GetDPHolding(clientcode)   
# print(Mofsl.GetDPHolding(clientcode))


# # PositionConversion
# print("--------------------------------PositionConversion--------------------------------")
# # "clientcode":"" "KAL005" Optional only for dealer
# PositionConversionInfo = {
#     "clientcode":clientcode,
#     "exchange":"NSE",
#     "scripcode":1660,
#     "quantity":1,
#     "oldproduct":"NORMAL",
#     "newproduct":"VALUEPLUS"
# }

# # Mofsl.PositionConversion(PositionConversionInfo)   
# print(Mofsl.PositionConversion(PositionConversionInfo))

# # GetReportMarginSummary 
# print("--------------------------------GetReportMarginSummary--------------------------------")
# # Mofsl.GetReportMarginSummary(clientcode)   
# print(Mofsl.GetReportMarginSummary(clientcode))

# # GetReportMarginDetail 
# print("--------------------------------GetReportMarginDetail--------------------------------")
# # Mofsl.GetReportMarginDetail(clientcode)   
# print(Mofsl.GetReportMarginDetail(clientcode))


# # GetLtp
# print("--------------------------------GetLtp--------------------------------")
# # "clientcode":"" "KAL005" Optional only for dealer
# LTPData = {
#     "clientcode":clientcode,
#     "exchange":"BSE",
#     "scripcode":500317
# }

# # Mofsl.GetLtp(LTPData)   
# print(Mofsl.GetLtp(LTPData))

# # GetInstrumentFile 
# print("--------------------------------GetInstrumentFile--------------------------------")
# # Mofsl.GetInstrumentFile(exchangename, clientcode)   
# print(Mofsl.GetInstrumentFile("NSEFO",clientcode))

# # GetOrderDetailByUniqueorderID 
# print("--------------------------------GetOrderDetailByUniqueorderID--------------------------------")
# # Mofsl.GetOrderDetailByUniqueorderID(uniqueorderid, clientcode)   
# print(Mofsl.GetOrderDetailByUniqueorderID("2600001T024312",clientcode))

# # GetTradeDetailByUniqueorderID 
# print("--------------------------------GetTradeDetailByUniqueorderID--------------------------------")
# # Mofsl.GetTradeDetailByUniqueorderID(uniqueorderid, clientcode)   
# # print(Mofsl.GetTradeDetailByUniqueorderID("0400057FIGN049",clientcode))

# # GetBrokerageDetail 
# print("--------------------------------GetBrokerageDetail--------------------------------")
# BrokerageDetailInfo = {
#     "clientcode":clientcode,
#     "exchangename":"NSE",
#     "series":"A"      
# }
# # Mofsl.GetBrokerageDetail(BrokerageDetailInfo)   
# print(Mofsl.GetBrokerageDetail(BrokerageDetailInfo))


# # Logout 
# print("--------------------------------Logout--------------------------------")
# # Mofsl.logout(clientcode)   
# print(Mofsl.logout(clientcode))

# # Trade Webhook
# print("--------------------------------TradeWebhook--------------------------------")
# # Mofsl.TradeWebhook(userid)   
# print(Mofsl.TradeWebhook(userid))


# --------------------------------------------------------------------------------------------------------
# -----------------------------------------------WebSocket------------------------------------------------
# --------------------------------------------------------------------------------------------------------


# Broadcast_connect   
def Broadcast_on_open(ws1):
    # print("########Broadcast_Opened########")
    # print("AuthValidate after connection opened")

    # Exchange -BSE, NSE, NSEFO, MCX, NSECD, NCDEX, BSEFO
    # Exchange Type- CASH,DERIVATIVES   Scrip Code-eg 532540

    Mofsl.Register("NSE", "CASH", 11536)
    # Mofsl.Register("BSE", "CASH", 532540)
    # Mofsl.Register("MCX", "DERIVATIVES", 245470)
    # Mofsl.Register("NSEFO", "DERIVATIVES",55917)
    # Mofsl.Register("NCDEX", "DERIVATIVES",59259)
    # Mofsl.Register("BSEFO", "DERIVATIVES",873973)

    # Mofsl.UnRegister("BSE", "CASH", 532540)


    # Index BSE, NSE
    # Mofsl.IndexRegister("NSE")
    # Mofsl.IndexRegister("BSE")

    # Mofsl.IndexUnregister("NSE")
    # Mofsl.IndexUnregister("BSE")

    # Broadcast Logout
    # Mofsl.Broadcast_Logout()


def Broadcast_on_message(ws1, message_type, message):
    
    if message_type == "Index":
        print(message)

    elif(message_type == "LTP"):
        print(message)
    elif(message_type == "MarketDepth"):
        print(message)
    elif(message_type == "DayOHLC"):
        print(message)
    elif(message_type == "DPR"):
        print(message)
    elif(message_type == "OpenInterest"):
        print(message)

    else:
        print(message)
    pass


    # print(message, message_type)
    

    
def Broadcast_on_close(ws1, close_status_code, close_msg):
    # print("########Broadcast_closed########")
    # print("Broadcast Connection Closed")
    print("Close Message : %s" %(close_msg))
    print("Close Message Code : %s" %(close_status_code)) 



# TradeStatus_connect
def TradeStatus_on_open(ws2):
    # print("########TradeStatus_Opened########")
    # print("TradeStatus AuthValidate after connection opened")

    # Trade Status
    Mofsl.Tradelogin()

    Mofsl.OrderSubscribe()
    Mofsl.TradeSubscribe()

    # Mofsl.OrderUnsubscribe()
    # Mofsl.TradeUnsubscribe()
 
    # Mofsl.Tradelogout()

def TradeStatus_on_message(ws2, message_type, message):

    if message_type == "TradeStatus":
        print(message)
    
    
def TradeStatus_on_close(ws2, close_status_code, close_msg):
    # print("########TradeStatus_closed########")
    # print("TradeStatus Connection Closed")
    print("Close Message : %s" %(close_msg))
    print("Close Message Code : %s" %(close_status_code)) 


# Assign the callbacks.
Mofsl._Broadcast_on_open = Broadcast_on_open
Mofsl._Broadcast_on_message = Broadcast_on_message
Mofsl._Broadcast_on_close = Broadcast_on_close

Mofsl._TradeStatus_on_open = TradeStatus_on_open
Mofsl._TradeStatus_on_message = TradeStatus_on_message
Mofsl._TradeStatus_on_close = TradeStatus_on_close


# # Connect 

# Mofsl.TradeStatus_connect()
# Mofsl.Broadcast_connect()

# --------------------------------------------------------------------------------------------------------
# -----------------------------------------------TCPSocket------------------------------------------------
# --------------------------------------------------------------------------------------------------------


# Broadcast_connect   
def TCPBroadcast_on_open():
    # print("########TCPBroadcast_Opened########")
    # print("AuthValidate after connection opened")

    # Exchange -BSE, NSE, NSEFO, MCX, NSECD, NCDEX, BSEFO
    # Exchange Type- CASH,DERIVATIVES   Scrip Code-eg 532540

    Mofsl.TCPRegister("NSE", "CASH", 11536)
    # Mofsl.TCPRegister("BSE", "CASH", 532540)
    # Mofsl.TCPRegister("MCX", "DERIVATIVES", 245470)
    # Mofsl.TCPRegister("NSEFO", "DERIVATIVES",55917)
    # Mofsl.TCPRegister("NCDEX", "DERIVATIVES",59259)
    # Mofsl.TCPRegister("BSEFO", "DERIVATIVES",873973)

    # Mofsl.TCPUnRegister("BSE", "CASH", 532540)


    # Index BSE, NSE
    # Mofsl.TCPIndexRegister("NSE")
    # Mofsl.TCPIndexRegister("BSE")

    # Mofsl.TCPIndexUnregister("NSE")
    # Mofsl.TCPIndexUnregister("BSE")

    # TCPBroadcast Logout
    # Mofsl.TCPBroadcast_Logout()

def TCPBroadcast_on_message(message_type, message):
    
    if message_type == "Index":
        print(message)

    elif(message_type == "LTP"):
        print(message)
    elif(message_type == "MarketDepth"):
        print(message)
    elif(message_type == "DayOHLC"):
        print(message)
    elif(message_type == "DPR"):
        print(message)
    elif(message_type == "OpenInterest"):
        print(message)

    else:
        print(message)
    pass


    # print(message, message_type)
    



# Assign the callbacks.
Mofsl._TCPBroadcast_on_open = TCPBroadcast_on_open
Mofsl._TCPBroadcast_on_message = TCPBroadcast_on_message


# # Connect 
# Mofsl.TCPBroadcast_connect()






