# !/usr/bin/env python3

from pytm import (
    TM,
    Actor,
    Boundary,
    Data,
    Dataflow,
    Datastore,
    Server,
    Lambda,
    Classification,
    DatastoreType,
)
from pytm.pytm import TLSVersion

tm = TM("Ecommerce WebApp AWS Threat Model")
tm.description = "Threat Model for an eCommerce Arquitecture in AWS with EC2, API Gateway, Lambda and DynamoDB"
tm.isOrdered = True
tm.mergeResponses = True

# ===== Boundaries =====
internet = Boundary("Internet")
aws_space = Boundary("AWS")
public_subnet = Boundary("Public Subnet")
private_subnet = Boundary("Private Subnet")

# ===== Actors =====
client = Actor("Cliente Web/App")
client.inBoundary = internet

# ===== Servers & Components =====
waf = Server("AWS WAF")
waf.inBoundary = aws_space

alb = Server("Application Load Balancer")
alb.inBoundary = aws_space
alb.controls.isHardened = True
alb.controls.sanitizesInput = True

frontend = Server("FrontEnd")
frontend.inBoundary = public_subnet
frontend.controls.sanitizesInput = True
frontend.controls.encodeOutput = True

apigw = Server("API Gateway")
apigw.inBoundary = public_subnet
apigw.controls.sanitizesInput = True
apigw.controls.authenticatesSource = True
apigw.controls.authorizesSource = True

webserver = Server("Web Server")
webserver.inBoundary = private_subnet
webserver.OS = "Amazon Linux"
webserver.controls.isHardened = True
webserver.controls.sanitizesInput = True
webserver.controls.encodesOutput = True
webserver.controls.authorizesSource = True

lambda_f = Lambda("Lambda")
lambda_f.inBoundary = private_subnet
lambda_f.controls.isHardened = True

dynamodb = Datastore("Amazon DynamoDB")
dynamodb.inBoundary = private_subnet
dynamodb.isSQL = False
dynamodb.maxClassification = Classification.SENSITIVE
dynamodb.storesPII = True
dynamodb.isEncryptedAtRest = True

s3 = Datastore("S3 Bucket - Web App Images")
s3.inBoundary = private_subnet
s3.isSql = False
s3.maxClassification = Classification.PUBLIC
s3.isEncryptedAtRest = False

# ===== Data =====
user_data = Data("User Data")
user_data.classification = Classification.SENSITIVE
user_data.isPII = True
user_data.isDestEncryptedAtRest = True

order_data = Data("Order Data")
order_data.classification = Classification.RESTRICTED
order_data.isDestEncryptedAtRest = True

# ===== Dataflows =====
client_to_waf = Dataflow(client, waf, "HTTPS Request (User Login, Orders)")
client_to_waf.protocol = "HTTPS"
client_to_waf.dstPort = 443
client_to_waf.tlsVersion = TLSVersion.TLSv12

waf_to_client = Dataflow(waf, client, "HTTPS Respond (Interface/Dashboard)")
waf_to_client.protocol = "HTTPS"
waf_to_client.dstPort = 443
waf_to_client.tlsVersion = TLSVersion.TLSv12

waf_to_alb = Dataflow(waf, alb, "Forward HTTPS")
waf_to_alb.protocol = "HTTPS"
waf_to_alb.dstPort = 443
waf_to_alb.tlsVersion = TLSVersion.TLSv12

#alb_to_waf = Dataflow(alb, waf, "Forward HTTPS")
#alb_to_waf.protocol = "HTTPS"
#alb_to_waf.dstPort = 443
#alb_to_waf.tlsVersion = TLSVersion.TLSv12

alb_to_front = Dataflow(alb, frontend, "HTTPS User Action to FrontEnd")
alb_to_front.protocol = "HTTPS"
alb_to_front.dstPort = 443
alb_to_front.tlsVersion = TLSVersion.TLSv12
alb_to_front.data = user_data

front_to_alb = Dataflow(frontend, alb, "HTTPS FrontEnd Action")
front_to_alb.protocol = "HTTPS"
front_to_alb.dstPort = 443
front_to_alb.tlsVersion = TLSVersion.TLSv12

front_to_apigw = Dataflow(frontend, apigw, "API Call to Gateway (HTTPS)")
front_to_apigw.protocol = "HTTPS"
front_to_apigw.dstPort = 443
front_to_apigw.tlsVersion = TLSVersion.TLSv12

apigw_to_front = Dataflow(apigw, frontend, "API Response (HTTPS)")
apigw_to_front.protocol = "HTTPS"
apigw_to_front.dstPort = 443
apigw_to_front.tlsVersion = TLSVersion.TLSv12

apigw_to_webserver = Dataflow(apigw, webserver, "API Request (HTTPS)")
apigw_to_webserver.protocol = "HTTPS"
apigw_to_webserver.dstPort = 443
apigw_to_webserver.tlsVersion = TLSVersion.TLSv12
apigw_to_webserver.usesSessionTojens = True

webserver_to_apigw = Dataflow(webserver, apigw, "Server Response (HTTPS)")
webserver_to_apigw.protocol = "HTTPS"
webserver_to_apigw.dstPort = 443
webserver_to_apigw.tlsVersion = TLSVersion.TLSv12
webserver_to_apigw.usesSessionTojens = True

apigw_to_lambda = Dataflow(apigw, lambda_f, "Invoke Lambda")
apigw_to_lambda.protocol = "HTTPS"
apigw_to_lambda.data = order_data

lambda_to_dynamodb = Dataflow(lambda_f, dynamodb, "Write Orders")
lambda_to_dynamodb.protocol = "HTTPS"
lambda_to_dynamodb.data = order_data

lambda_to_s3 = Dataflow(lambda_f, s3, "Upload/Read Images")
lambda_to_s3.protocol = "HTTPS"

dynamodb_to_s3 = Dataflow(dynamodb, s3, "Get Images")


# ===== Threat Model Execution =====
if __name__ == "__main__":
    tm.process()