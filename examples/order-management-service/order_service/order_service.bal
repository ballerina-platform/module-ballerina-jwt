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

import ballerina/http;

type OrderItem record {|
    string category;
    string code;
    int qty;
|};

type Order record {|
    string id;
    string name;
    OrderItem[] items;
|};

type UpdateOrder record {|
    string name;
    OrderItem[] items;
|};

map<Order> ordersMap = {};

http:Client inventoryClient = check new("https://localhost:9091",
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
            }
        }
    }
};

listener http:Listener orderEP = new(9090,
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);

service /ordermgt on orderEP {

    @http:ResourceConfig {
        auth: [
            {
                jwtValidatorConfig: config,
                scopes: "add_order"
            }
        ]
    }
    resource function post 'order(@http:Payload Order 'order) returns http:Created|http:InternalServerError {
        string orderId = 'order.id;
        ordersMap[orderId] = 'order;
        http:InternalServerError? result = updateInventory('order.items);
        if result is http:InternalServerError {
            return result;
        }
        return <http:Created>{
            body: {
                status: "Order '" + orderId + "' created."
            },
            headers: {"Location": "http://localhost:9090/ordermgt/order/" + orderId}
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
    resource function put 'order/[string orderId](@http:Payload UpdateOrder updateOrder)
                                           returns http:Ok|http:BadRequest|http:InternalServerError {
        Order? existingOrder = ordersMap[orderId];
        if existingOrder is Order {
            http:InternalServerError? result = reverseInventoryUpdate(existingOrder.items);
            if result is http:InternalServerError {
                return result;
            }
            existingOrder.name = updateOrder.name;
            existingOrder.items = updateOrder.items;
            ordersMap[orderId] = existingOrder;
            result = updateInventory(existingOrder.items);
            if result is http:InternalServerError {
                return result;
            }
            return <http:Ok>{
                body: {
                    status: "Order '" + orderId + "' updated."
                }
            };
        }
        return <http:BadRequest>{
            body: {
                status: "Order '" + orderId + "' cannot be found."
            }
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
    resource function delete 'order/[string orderId]() returns http:Ok|http:InternalServerError {
        Order 'order = ordersMap.remove(orderId);
        http:InternalServerError? result = reverseInventoryUpdate('order.items);
        if result is http:InternalServerError {
            return result;
        }
        return <http:Ok>{
            body: {
                status: "Order '" + orderId + "' removed."
            }
        };
    }

    resource function get 'order/[string orderId]() returns http:Ok|http:NotFound {
        if ordersMap.hasKey(orderId) {
            return <http:Ok>{
                body: {
                    'order: ordersMap[orderId].toJson()
                }
            };
        }
        return <http:NotFound>{
            body: {
                status: "Order '" + orderId + "' cannot be found."
            }
        };
    }
}

function updateInventory(OrderItem[] items) returns http:InternalServerError? {
    http:Response|http:ClientError response = inventoryClient->put("/inventory", items);
    if response is http:ClientError {
        return {
            body: {
                status: "Failed to update the inventory." + response.message()
            }
        };
    }
}

function reverseInventoryUpdate(OrderItem[] items) returns http:InternalServerError? {
    http:Response|http:ClientError response = inventoryClient->put("/inventory/reverse", items);
    if response is http:ClientError {
        return {
            body: {
                status: "Failed to update the inventory." + response.message()
            }
        };
    }
}
