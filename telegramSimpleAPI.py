from requests import post
file = open('targeturl.txt','r')
targetURL= file.read()
##telegram send message
text = "Recon task on target: "+targetURL+" Completed"
#Replace BOT-TOKEN and CHATID in the following area to send you messages using your bot to you
URL= "https://api.telegram.org/bot<telegramBotToken>/SendMessage?chat_id=<ChatID>&text="+text
payload = {"UrlBox":URL,
	"AgentList":"Mozilla Firefox",
    "VersionsList":"HTTP/1.1",
    "MethodList":"POST"
    }
post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx",payload)
print ("Telegram notification has been sent")
