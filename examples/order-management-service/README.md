# Secured Order Management Service with JWT Auth

## Overview

This guide explains how to secure an 'Order Management Service' (RESTful service) with JWT Auth using Ballerina. 
The following figure illustrates a high-level design diagram of the complete use case.

![Securing Microservice with JWT](./order-management-service.png)

**NOTE**: For this guide, we are focussing on the security of 'Order Service' only.

Here, the 'Order Service' receives the traffic only from the 'API Gateway'.
- The 'API Gateway' intercepts the request from the end-user, extracts the token, and then talks to the 'STS' connected 
  to validate the token.
- After validating the token, the 'STS' issues a new JWT signed by itself. This JWT includes the user details.
- The 'API Gateway' passes the new JWT to the 'Order Management Service', and it needs only trust this STS to accept 
  the token as valid. The 'Order Management Service' validates the signature of the JWT to make sure that it's issued 
  by the 'STS' it trusts. Apart from the signature validation, the 'Order Management Service' also does the issuer and 
  audience validation.
- The 'Order Service' talks to 'Inventory Service' with mTLS (mutual TLS).

In this approach, JWT helps us to achieve two things. First, it helps to pass the end-user context across microservices 
in a manner that can’t be forged. Because the claims set of the JWT is signed by the STS, no microservice can change 
it's content without invalidating its signature. Also, JWT helps to secure service-to-service communications. One 
microservice can access another microservice only if it carries a valid JWT issued by the trusted STS. Any recipient 
microservice rejects any request without a valid JWT.

## Implementation

**NOTE**: To get started with the implementation we need to have the 'Inventory Service' to be ready. But, since we are 
focussing only on the 'Order Service' by this guide, the implementation details of the 'Inventory Service' are not 
explained. Refer to [`examples/order-management-service/inventory_service`](./inventory_service) for the implementation.

- Now, we can get started with the Ballerina service; 'Order Service', which is a RESTful service that serves the 
  order management requests. We will look at securing multiple resources exposed by 'Order Service' to match with the 
  different security requirements.

  - **Create Order** : Order creation should only be allowed for authenticated users.
  - **Retrieve Order** : Retrieval of the order details should be allowed for all the users.
  - **Update Order** : Updating order details should only be allowed for "admin" users.
  - **Delete Order** : Deletion of the order should only be allowed for "admin" users.
  
- Authentication is enabled by setting the `auth` attribute of `http:ServiceConfig` or `http:ResourceConfig`. If we 
  configure the `auth` attribute of `http:ServiceConfig` it will be applied to all the resources of the configured HTTP
  Service. Also, the security enforcement that is done for the service using the `http:ServiceConfig` can be overridden 
  by the `http:ResourceConfig` annotation for a specific API(s).
  
- For this example 'Order Service', we need to configure the `auth` attribute of all the resources except the "Retrieve 
  Order" resource, since we need to allow that for all the users.

- Ballerina uses the concept of 'scope' as the way of expressing authorization. Multiple scopes can be assigned to a 
  user, and scopes can then be validated while enforcing authorization. To express that a certain service or resource 
  require a scope, we have used the `scopes` annotation attribute of the `auth` annotation attribute.
  
- For this example 'Order Service', we need to configure the `scope` attribute for all the resources except the
  "Retrieve Order" resource, since we need to allow that for all the users.

**NOTE**: For the simplicity of the article, we use an in-memory map for storing order data, and a 'Mock STS' is used 
for validating the JWT signature using JWKs. Refer to [`examples/order-management-service/sts`](./sts) for the implementation.

## Testing

We can run the 'Order Service' that we developed above, in our local environment. To complete the design diagram 
illustrated above, we have to run the 'Mock STS', and the 'Inventory Service' first. 

Open the terminal and navigate to [`examples/order-management-service/sts`](./sts) directory and execute the following command.
```shell
$ bal run
```

The successful execution of the service should show us the following output.
```shell
Compiling source
        jwt/sts:1.0.0

Running executable

[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9445
```

Now, navigate to [`examples/order-management-service/inventory_service`](./inventory_service) directory and execute the same command.
The successful execution of the service should show us the following output.
```shell
Compiling source
        jwt/inventory_service:1.0.0

Running executable

[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9091
```

Now, navigate to [`examples/order-management-service/order_service`](./order_service) directory and execute the same command.
The successful execution of the service should show us the following output.
```shell
Compiling source
        jwt/order_service:1.0.0

Running executable

[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9090
```

Now, we can test authentication and authorization checks being enforced on different functions of the 'Order Service' 
by sending HTTP requests. For example, we have used the CURL commands to test each operation of the 'Order Service' as 
follows.

### Create Order

#### Without authentication

```shell
curl -k -v -H "Content-Type: application/json" \
-d '{"id": "100500", "name": "Sample order", "items": [{"category": "electronics", "code": "SOWH1000XM4", "qty": 2}, {"category": "books", "code": "978-1617295959", "qty": 1}]}' \
"https://localhost:9090/ordermgt/order"
```

Output:
```shell
< HTTP/1.1 401 Unauthorized
< content-length: 0
< server: ballerina
< date: Tue, 24 Aug 2021 06:33:52 +0530
```

#### Authenticating as the 'counter' user, who has 'add_order' permission

```shell
curl -k -v -H "Content-Type: application/json" \
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0TkRObFpEVTFPR0ZrTmpGaU1RIn0.eyJpc3MiOiJ3c28yIiwgInN1YiI6ImNvdW50ZXIiLCAiYXVkIjoiYmFsbGVyaW5hIiwgImV4cCI6MTk0NTIzODg5NCwgIm5iZiI6MTYyOTg3ODg5NCwgImlhdCI6MTYyOTg3ODg5NCwgImp0aSI6ImY1YWRlZDUwNTg1YzQ2ZjJiOGNhMjMzZDBjMmEzYzlkIiwgInNjb3BlIjoiYWRkX29yZGVyIn0.FMDL-Y8zMtAW7vBVeEbwf_8ynSKdjAkuEBVJpoGds06Z2cOrL3WPZYswnbUOzULBnOXQJQEnK-P-QmypvqP0NWGpzfoC5QMqg0FhPvxyglP1QNYbrS_5tZFM_7Nn7tBFZxiBq666AzjDyhZ2jc39X9rftV0m8p4yyFdSI4KFiEzQ8eOWVVOIg3ejQ0ruDlSVvwx3lXe03XYmrhQp0m-_KYm-SGV3HTZttbo00A250pVY1QL137WDgeeDtGchOfjvM9G-UL8t3sw1Lyoq4OzblHEJJQOJnfRLM_nFKeULuAtt5k_UwmQRlV-XrgxMk0lu6KvYt1-Sa1HMiS8aIvrwig" \
-d '{"id": "100500", "name": "Sample order", "items": [{"category": "electronics", "code": "SOWH1000XM4", "qty": 2}, {"category": "books", "code": "978-1617295959", "qty": 1}]}' \
"https://localhost:9090/ordermgt/order"
```

Output:
```shell
< HTTP/1.1 201 Created
< Location: http://localhost:9090/ordermgt/order/100500
< content-type: application/json
< content-length: 36
< server: ballerina
< date: Tue, 24 Aug 2021 06:34:05 +0530

{"status":"Order '100500' created."}
```

### Retrieve Order

```shell
curl -k -v "https://localhost:9090/ordermgt/order/100500"
```

Output:
```shell
< HTTP/1.1 200 OK
< content-type: application/json
< content-length: 70
< server: ballerina
< date: Tue, 24 Aug 2021 06:34:20 +0530

{"id":"100500", "name":"Sample order", "items":[{"category":"electronics", "code":"SOWH1000XM4", "qty":2}, {"category":"books", "code":"978-1617295959", "qty":1}]}
```

### Update Order

#### Without authentication

```shell
curl -k -v -X PUT -H "Content-Type:application/json" \
-d '{"name": "Updated order", "items": [{"category": "electronics", "code": "SOWH1000XM4", "qty": 1}]}' \
"https://localhost:9090/ordermgt/order/100500"
```

Output:
```shell
< HTTP/1.1 401 Unauthorized
< content-length: 0
< server: ballerina
< date: Tue, 24 Aug 2021 06:34:32 +0530
```

#### Authenticating as 'counter' user, who has 'add_order' permission

```shell
curl -k -v -X PUT -H "Content-Type:application/json" \
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0TkRObFpEVTFPR0ZrTmpGaU1RIn0.eyJpc3MiOiJ3c28yIiwgInN1YiI6ImNvdW50ZXIiLCAiYXVkIjoiYmFsbGVyaW5hIiwgImV4cCI6MTk0NTIzODg5NCwgIm5iZiI6MTYyOTg3ODg5NCwgImlhdCI6MTYyOTg3ODg5NCwgImp0aSI6ImY1YWRlZDUwNTg1YzQ2ZjJiOGNhMjMzZDBjMmEzYzlkIiwgInNjb3BlIjoiYWRkX29yZGVyIn0.FMDL-Y8zMtAW7vBVeEbwf_8ynSKdjAkuEBVJpoGds06Z2cOrL3WPZYswnbUOzULBnOXQJQEnK-P-QmypvqP0NWGpzfoC5QMqg0FhPvxyglP1QNYbrS_5tZFM_7Nn7tBFZxiBq666AzjDyhZ2jc39X9rftV0m8p4yyFdSI4KFiEzQ8eOWVVOIg3ejQ0ruDlSVvwx3lXe03XYmrhQp0m-_KYm-SGV3HTZttbo00A250pVY1QL137WDgeeDtGchOfjvM9G-UL8t3sw1Lyoq4OzblHEJJQOJnfRLM_nFKeULuAtt5k_UwmQRlV-XrgxMk0lu6KvYt1-Sa1HMiS8aIvrwig" \
-d '{"name": "Updated order", "items": [{"category": "electronics", "code": "SOWH1000XM4", "qty": 1}]}' \
"https://localhost:9090/ordermgt/order/100500"
```

Output:
```shell
< HTTP/1.1 403 Forbidden
< content-length: 0
< server: ballerina
< date: Tue, 24 Aug 2021 06:34:55 +0530
```

#### Authenticating as 'admin' user, who has 'add_order, update_order, cancel_order' permissions

```shell
curl -k -v -X PUT -H "Content-Type:application/json" \
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0TkRObFpEVTFPR0ZrTmpGaU1RIn0.eyJpc3MiOiJ3c28yIiwgInN1YiI6ImFkbWluIiwgImF1ZCI6ImJhbGxlcmluYSIsICJleHAiOjE5NDUyMzY1OTksICJuYmYiOjE2Mjk4NzY1OTksICJpYXQiOjE2Mjk4NzY1OTksICJqdGkiOiJkMWI4NjNlNjc1N2M0ZjJlYjViMjM3YjI5ZmRhOGZhZSIsICJzY29wZSI6WyJhZGRfb3JkZXIiLCAidXBkYXRlX29yZGVyIiwgImNhbmNlbF9vcmRlciJdfQ.XxThNFztJTpn9FIk-9JfEm_xF8sbTwGnNa5bOl-l4lb3KfeV5ojAKEmjenpQR_2YctT2GM68mxunXP4CTxXoAVHAYWDmV10wkR4r7R6LO3wDJDqr7POC3zwtM-n9Ro-gWJEio-SLYw04kxExvjsE1aFa7pRJFuAFDIdAqnXkEaHLXshmOCgxYhAMzdgBQzUtBo7QmjQZf_0kPUioPpNNsDV4bGLQTeZo-SCZhfhvbHBrUsY2VVleUg0_gNVMmT0ySFQ8Jci4CaiglYrxQN9byS38_9qXtWINYEMbtApHaeyl4-0YvY5p8EbJes2ep_r0Q_Od6FQzGekFAVO4gSE6Zw" \
-d '{"name": "Updated order", "items": [{"category": "electronics", "code": "SOWH1000XM4", "qty": 1}]}' \
"https://localhost:9090/ordermgt/order/100500"
```

Output:
```shell
< HTTP/1.1 200 OK
< content-type: application/json
< content-length: 36
< server: ballerina
< date: Tue, 24 Aug 2021 06:35:07 +0530

{"status":"Order '100500' updated."}
```

### Cancel Order

#### Authenticating as 'admin' user, who has 'add_order, update_order, cancel_order' permissions

```shell
curl -k -v -X DELETE \
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0TkRObFpEVTFPR0ZrTmpGaU1RIn0.eyJpc3MiOiJ3c28yIiwgInN1YiI6ImFkbWluIiwgImF1ZCI6ImJhbGxlcmluYSIsICJleHAiOjE5NDUyMzY1OTksICJuYmYiOjE2Mjk4NzY1OTksICJpYXQiOjE2Mjk4NzY1OTksICJqdGkiOiJkMWI4NjNlNjc1N2M0ZjJlYjViMjM3YjI5ZmRhOGZhZSIsICJzY29wZSI6WyJhZGRfb3JkZXIiLCAidXBkYXRlX29yZGVyIiwgImNhbmNlbF9vcmRlciJdfQ.XxThNFztJTpn9FIk-9JfEm_xF8sbTwGnNa5bOl-l4lb3KfeV5ojAKEmjenpQR_2YctT2GM68mxunXP4CTxXoAVHAYWDmV10wkR4r7R6LO3wDJDqr7POC3zwtM-n9Ro-gWJEio-SLYw04kxExvjsE1aFa7pRJFuAFDIdAqnXkEaHLXshmOCgxYhAMzdgBQzUtBo7QmjQZf_0kPUioPpNNsDV4bGLQTeZo-SCZhfhvbHBrUsY2VVleUg0_gNVMmT0ySFQ8Jci4CaiglYrxQN9byS38_9qXtWINYEMbtApHaeyl4-0YvY5p8EbJes2ep_r0Q_Od6FQzGekFAVO4gSE6Zw" \
"https://localhost:9090/ordermgt/order/100500"
```

Output:
```shell
< HTTP/1.1 200 OK
< content-type: application/json
< content-length: 36
< server: ballerina
< date: Tue, 24 Aug 2021 06:35:26 +0530

{"status":"Order '100500' removed."}
```

## Deployment

Once we are done with the development, we can deploy the service using any of the methods that are listed below.

### Deploying Locally

As the first step, we can build Ballerina executable files (.jar) of the microservices that we developed above. Open the 
terminal and navigate to [`examples/order-management-service/sts`](./sts), 
[`examples/order-management-service/inventory_service`](./inventory_service)
and [`examples/order-management-service/order_service`](./order_service) directories, and execute the following command 
for each of them.
```shell
$ bal build
```

The successful execution of the above command should show us the following outputs in order.
```shell
Compiling source
        jwt/sts:1.0.0

Generating executable
        target/bin/sts.jar
```

```shell
Compiling source
        jwt/inventory_service:1.0.0

Generating executable
        target/bin/inventory_service.jar
```

```shell
Compiling source
        jwt/order_service:1.0.0

Generating executable
        target/bin/order_service.jar
```

Once the `*.jar` files are created inside the `target/bin` directories, we can run the microservices with the following 
commands in order.
```shell
$ bal run target/bin/sts.jar
$ bal run target/bin/inventory_service.jar
$ bal run target/bin/order_service.jar
```

The successful execution of the services will show us the following outputs in order.
```shell
[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9445
```

```shell
[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9091
```

```shell
[ballerina/http] started HTTPS/WSS listener 0.0.0.0:9090
```

### Deploying Code to Cloud

Ballerina code to cloud supports generating the deployment artifacts of the Docker and Kubernetes.
Refer to [Code to Cloud](https://ballerina.io/learn/user-guide/deployment/code-to-cloud/) guide for more information.

## Observability

HTTP/HTTPS based Ballerina services and any client connectors are observable by default.
[Observing Ballerina Code](https://ballerina.io/learn/user-guide/observability/observing-ballerina-code/) guide provides 
information on enabling Ballerina service observability with some of its supported systems.
