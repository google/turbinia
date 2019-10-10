

#Sends notfications via email
def sendmail(message):
    import logging
    from turbinia import config
    log=logging.getLogger('turbinia')
    EMAIL_NOTIFICATIONS = config.EMAIL_NOTIFCATIONS
    EMAIL_HOST_ADDRESS = config.EMAIL_HOST_ADDRESS
    EMAIL_PORT = int(config.EMAIL_PORT)

    EMAIL_ADDRESS = config.EMAIL_ADDRESS
    EMAIL_PASSWORD = config.EMAIL_PASSWORD

    RECIEVING_ADDRESS = config.RECIEVING_ADDRESS
    try:
        if EMAIL_NOTIFICATIONS == True:
            #Imports SMTP and  MIME(The format used for emails)
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            import smtplib

            #Puts message in MIME format
            msg = MIMEMultipart()
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = RECIEVING_ADDRESS
            msg['Subject'] = 'Notifcation from Turbina'
            msg.attach(MIMEText(message))

            #start SMTP
            server = smtplib.SMTP(EMAIL_HOST_ADDRESS,EMAIL_PORT)

            # identify to mail server
            server.ehlo()

            # secure email using TLS
            server.starttls()

            # reidentify and login to mail account
            server.ehlo()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

            server.sendmail(EMAIL_ADDRESS, RECIEVING_ADDRESS,msg.as_string())

            #terminate connection
            server.quit()
            print('Email notification sent')
        else:
            print('Email notifications are disabled')
            pass
    except Exception as e:
            print(e)
            print('Email failed to send, check config')
            pass
