// Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/cache;
import ballerina/http;
import order_service.representations as rep;

// In memory storage used to store the orders
map<rep:Order> ordersMap = {};

http:Client inventoryClient = check new ("https://localhost:9091",
    secureSocket = {
        cert: "./resources/public.crt",
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);

http:JwtValidatorConfig config = {
    issuer: "wso2",
    audience: "ballerina",
    signatureConfig: {
        jwksConfig: {
            url: "https://localhost:9445/oauth2/jwks",
            clientConfig: {
                secureSocket: {
                    cert: "./resources/public.crt"
                }
            },
            cacheConfig: {
                capacity: 10,
                evictionFactor: 0.25,
                evictionPolicy: cache:LRU,
                defaultMaxAge: -1
            }
        }
    },
    cacheConfig: {
        capacity: 10,
        evictionFactor: 0.25,
        evictionPolicy: cache:LRU,
        defaultMaxAge: -1
    }
};

listener http:Listener orderEP = new (9090, 
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);

service /'order on orderEP {

    @http:ResourceConfig {
        auth: [
            {
                jwtValidatorConfig: config,
                scopes: "add_order"
            }
        ]
    }
    resource function post .(@http:Payload rep:Order 'order) returns rep:OrderCreated|error {
        string orderId = 'order.id;
        ordersMap[orderId] = 'order;
        check updateInventoryQty('order.items, rep:DECREASE);
        return {
            body: {status: "Order '" + orderId + "' created."},
            headers: {"Location": "http://localhost:9090/order/" + orderId}
        };
    }

    @http:ResourceConfig {
        auth: [
            {
                jwtValidatorConfig: config,
                scopes: "update_order"
            }
        ]
    }
    resource function put [string orderId](@http:Payload rep:UpdateOrder updateOrder)
                                            returns rep:OrderUpdated|rep:OrderNotFound|error {
        rep:Order? existingOrder = ordersMap[orderId];
        if existingOrder is rep:Order {
            check updateInventoryQty(existingOrder.items, rep:INCREASE);
            existingOrder.name = updateOrder.name;
            existingOrder.items = updateOrder.items;
            ordersMap[orderId] = existingOrder;
            check updateInventoryQty(existingOrder.items, rep:DECREASE);
            return <rep:OrderUpdated>{
                body: {status: "Order '" + orderId + "' updated."}
            };
        }
        return <rep:OrderNotFound>{
            body: {status: "Order '" + orderId + "' cannot be found."}
        };
    }

    @http:ResourceConfig {
        auth: [
            {
                jwtValidatorConfig: config,
                scopes: "cancel_order"
            }
        ]
    }
    resource function delete [string orderId]() returns rep:OrderCanceled|rep:OrderNotFound|error {
        if ordersMap.hasKey(orderId) {
            rep:Order 'order = ordersMap.remove(orderId);
            check updateInventoryQty('order.items, rep:INCREASE);
            return <rep:OrderCanceled>{
                body: {status: "Order '" + orderId + "' removed."}
            };
        }
        return <rep:OrderNotFound>{
            body: {status: "Order '" + orderId + "' cannot be found."}
        };
    }

    resource function get [string orderId]() returns rep:Order|http:NotFound {
        if ordersMap.hasKey(orderId) {
            return <rep:Order>ordersMap[orderId];
        }
        return {body: {status: "Order '" + orderId + "' cannot be found."}};
    }
}

function updateInventoryQty(rep:OrderItem[] items, rep:InventoryOperation operation) returns error? {
    json|http:ClientError response = inventoryClient->put("/inventory/" + operation, items);
    if response is http:ClientError {
        return error("Failed to " + operation + " the inventory quantity.", response);
    }
}
