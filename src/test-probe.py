import logging
import json
import base64
import yaml
import os
from kubernetes.client import ApiException
import kubernetes


#### K8s-native Environment Variables #####
# code is intended to run inside a k8s pod
# by default, k8s exports several useful shell variables 
# which can be called by any container process, like so:
APISERVER_HOST = os.environ.get('KUBERNETES_SERVICE_HOST')
APISERVER_PORT = os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS')

if APISERVER_HOST and APISERVER_PORT:
    raise ValueError("ERROR: Unable to determine URL for kubernetes apiserver. Host or port is missing.")

#### User-defined Environment Variables #####
if os.environ.get('LOG_LEVEL'):
    LOG_LEVEL = os.environ.get('LOG_LEVEL').upper()
else:
    LOG_LEVEL = "INFO"

#### Configure Logger ####
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

#### Configure K8s client ####
configuration = kubernetes.client.Configuration()
configuration.host = f"https://{APISERVER_HOST}:{APISERVER_PORT}"

## SSL setup
# by default, the directory in which k8s service account files is here:
# /var/run/secrets/kubernetes.io/serviceaccount
# the ca.crt and other files are mounted to the pod at this path
configuration.verify_ssl = True 
configuration.ssl_ca_cert = '/var/run/secerts/kuberenetes.io/serviceaccount/ca.crt'

## API token setup
# There are multiple ways to retrieve the api token
# for the service account.
# Assuming the service account which created your pod is making the api call, 
# then you can load this as well
with open('/var/run/secerts/kuberenetes.io/serviceaccount/token') as f:
     token = f.read()
# otherwise, provide the correct token via a different file, or a shell var, like so:
# token = os.environ.get('SA_TOKEN')

if isinstance(token, bytes):
    token = token.decode()

configuration.api_key_prefix['authorization'] = 'Bearer'
configuration.api_key['authorization'] = token

with kubernetes.client.ApiClient(configuration) as api_client:

    # all methods on the following two objects wrap this generic method: kubernetes.client.ApiClient().call_api()
    core_apis = kubernetes.client.CoreV1Api(api_client)
    custom_apis = kubernetes.client.CustomObjectsApi(api_client)

    ####> SAMPLE CORE API CALL <####

    # Example Core V1 Api call:
    namespace = "mynamespace"
    secret_name = "mysecret"
    secret, sec_http_resp_code, sec_http_resp_headers = core_apis.read_namespaced_secret_with_http_info(secret_name, namespace=namespace)

    # Example error handling:
    if not isinstance(secret, kubernetes.client.models.V1Secret):
        # Rationale:
        # The Core V1 Apis should always return some kind of object model
        # Immediately after an api call, is it likely undesirable that 'secret' should have any other object type
        # If secret is none or some other type, then this is unexpected
        raise TypeError(f"ERROR: Object called 'secret' is type={type(secret)}. Object is expected to have type=kubernetes.client.models.V1Secret")
    
    # most V1CoreApi objects and child objects, like V1Secret, have a .to_dict() method for easy conversion
    secret = secret.to_dict()

    # suppose the k8s secret has data fields called 'ca.crt' and 'token'
    # we can just access them normally like so:
    encoded_ca_crt = secret['data']['ca.crt']
    decoded_ca_crt = base64.standard_b64decode( encoded_ca_crt) # All secret data returned from the apiserver is base64 encoded
    encoded_token = secret['data']['token']
    decoded_token = base64.standard_b64decode( encoded_token )


    ####> SAMPLE CUSTOM API CALL <####
