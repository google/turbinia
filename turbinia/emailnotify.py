import smtplib
from turbinia import config
from turbinia import 


#Sends notfications via email

def sendmail(message):
    EMAIL_NOTIFICATIONS = config.EMAIL_NOTIFCATIONS
    EMAIL_HOST_ADDRESS = config.EMAIL_HOST_ADDRESS
    EMAIL_PORT = int(config.EMAIL_PORT)

    EMAIL_ADDRESS = config.EMAIL_ADDRESS
    EMAIL_PASSWORD = config.EMAIL_PASSWORD

    RECIEVING_ADDRESS = config.RECIEVING_ADDRESS
    try:
        if EMAIL_NOTIFICATIONS == True:
            from email.mime.multipart import MIMEMultipart 
            from email.mime.text import MIMEText
            import smtplib
            msg = MIMEMultipart()
            #Creates message
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = RECIEVING_ADDRESS
            msg['Subject'] = 'Notifcation from Turbina'
            msg.attach(MIMEText(message))
            server = smtplib.SMTP(EMAIL_HOST_ADDRESS,EMAIL_PORT)

            # identify to mail server
            server.ehlo()

            # secure email using TLS
            server.starttls()

            # reidentify and login to mail account
            server.ehlo()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

            server.sendmail(EMAIL_ADDRESS, RECIEVING_ADDRESS,msg.as_string())

            server.quit()
        else:
            pass
    except Exception as e:
            print(e)
            print('Email failed to send, check config')
            pass
        

config.EMAIL_HOST_ADDRESS
