import route53_dns
import pytz
from datetime import datetime
import parsedatetime
import ssl, socket
import OpenSSL
from OpenSSL import crypto

import pprint
import logging
import letslambda

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger("letslambda")
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


S3_BUCKET = 'hello.raditha.com'
# Replace sender@example.com with your "From" address.
# This address must be verified with Amazon SES.
SENDER = "Raditha Via SES <raditha@raditha.com>"

# Replace recipient@example.com with a "To" address. If your account 
# is still in the sandbox, this address must be verified.
RECIPIENT = "raditha@raditha.com"

# Specify a configuration set. If you do not want to use a configuration
# set, comment the following variable, and the 
# ConfigurationSetName=CONFIGURATION_SET argument below.
# CONFIGURATION_SET = "ConfigSet"

# If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
AWS_REGION = "us-east-1"



def send_mail(csr):
    # The subject line for the email.
    SUBJECT = "CSR generated for expiring certificate"
    
    # The HTML body of the email.
    BODY_HTML = """<html>
    <head></head>
    <body>
      <h1>CSR</h1>
      <pre>{0}</pre>
    </body>
    </html>
                """            
    
    # The character encoding for the email.
    CHARSET = "UTF-8"
    
    # Create a new SES resource and specify a region.
    client = boto3.client('ses',region_name=AWS_REGION)
    
    # Try to send the email.
    try:
        #Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML.format(csr),
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': csr,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
            # If you are not using a configuration set, comment or delete the
            # following line
            #ConfigurationSetName=CONFIGURATION_SET,
        )
        print(response)
    # Display an error if something goes wrong.    
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['ResponseMetadata']['RequestId'])
    
    
def request_proprietory_certificate(conf, domain):
    (csr, key) = letslambda.generate_certificate_signing_request(conf, domain)

    
    pem_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("ascii")

    return (crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr), pem_private_key)

def lambda_handler(event, context):
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=AWS_REGION))
    conf = letslambda.load_config(s3_client, S3_BUCKET, 'letslambda.yml')
        
    conf['s3_client'] = s3_client
    conf['s3_bucket'] = S3_BUCKET
    conf['letslambda_config'] = "letslambda.yml"
    conf['kms_key'] = "AES256"
        
    zones = route53_dns.get_hosted_zones(conf, {'region': 'us-east-1'})
    for hostname in zones:
        try:
            cert = ssl.get_server_certificate((hostname, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            print(hostname, x509.get_issuer().commonName)
            print(x509.get_notAfter())
            if letslambda.is_certificate_expired(conf, None, x509):
                csr, private = request_proprietory_certificate(conf, {'name': x509.get_subject().CN, 
                                                             'countryName': x509.get_subject().C or 'LK'})
                
                send_mail(csr)
                
        except socket.gaierror:
            pass




