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

type UpdateRequest record {|
    string code;
    int qty;
|};

type OrderItem record {|
    string category;
    string code;
    int qty;
|};

listener http:Listener inventoryEP = new(9091,
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        },
        mutualSsl: {
            verifyClient: http:REQUIRE,
            cert: "./resources/public.crt"
        }
    }
);

service /inventory on inventoryEP {
    resource function put .(@http:Payload OrderItem[] orderItems) returns http:Ok {
        foreach OrderItem orderItem in orderItems {
            InventoryItem item = filterInventoryItem(orderItem.category, orderItem.code);
            item.qty -= orderItem.qty;
        }
        return {};
    }

    resource function put reverse(@http:Payload OrderItem[] orderItems) returns http:Ok {
        foreach OrderItem orderItem in orderItems {
            InventoryItem item = filterInventoryItem(orderItem.category, orderItem.code);
            item.qty += orderItem.qty;
        }
        return {};
    }
}

function filterInventoryItem(string itemCategory, string itemCode) returns InventoryItem {
    table<InventoryItem> key(code) inventoryTable = <table<InventoryItem> key(code)>inventory[itemCategory];
    return inventoryTable.get(itemCode);
}
