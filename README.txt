Implementation guide sdkversion Python 2.3 Release - 31/08/2023

1. Install required packages 
	Run following command in terminal to install required packages :
	pip install -r requirements.txt
	
2. ApiKey
	ApiKey will be obtain from website 

3. userid, password, clientcode, Two_FA 
	1. userid and password is your trading account username and password
	2. clientcode only needed in case of dealer, else always keep
	   clientcode = None
	3. Two_FA as per user defined DOB or PAN in str format

4. Set Url
	Enter Base Url for LIVE or UAT Testing 
	1. For live 
	   Base_Url = "https://openapi.motilaloswal.com"
	2. For UAT
	   Base_Url = "https://uatopenapi.motilaloswal.com"

5. Initialize MofslOpenApi
	Initialize MofslOpenApi using Apikey and Base_Url

6. Uncomment print statement to execute
	Loginrequest will always be first request with each following request 
		
	   
# -----------------------------------------------WebSocket------------------------------------------------

1. Repeat all above Instructions 

2. Keep Loginrequest Uncomment for Validation to use WebSocket

3. Uncomment Mofsl.Broadcast_connect() to use OpenAPI Broadcast Websocket Broadcast 

	To Register or Unregister script, in Broadcast_on_open(ws1) Uncomment
	1. Register script
		Mofsl.Register("BSE", "CASH", 532543)
	2. Unregister script
		Mofsl.UnRegister("BSE", "CASH", 532543)

	To Register or Unregister Index, in Broadcast_on_open(ws1) Uncomment
	1. Register Index 
		Mofsl.IndexRegister("NSE")
	2. Unregister Index
		Mofsl.IndexUnregister("NSE")

4. Uncomment Mofsl.TradeStatus_connect() to use OpenAPI Trade Websocket 

	1. To send Request for Authorization, in TradeStatus_on_open(ws1) Uncomment
		Mofsl.Tradelogin()
	2. To send Request for TradeSubscription, in TradeStatus_on_open(ws1) Uncomment
		Mofsl.TradeSubscribe()
	3. To send Request for TradeUnsubscription, in TradeStatus_on_open(ws1) Uncomment
		Mofsl.TradeUnsubscribe()
	4. To send Request for Logout, in TradeStatus_on_open(ws1) Uncomment
		Mofsl.Tradelogout()
	
5. Uncomment Mofsl.TCPBroadcast_connect() to use OpenAPI TCPBroadcast Websocket  

	Follow similar process for Mofsl.Broadcast_connect()




