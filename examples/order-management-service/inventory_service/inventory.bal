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

type ElectronicItem record {|
    readonly string code;
    string brand;
    string model;
    string price;
    int qty;
|};

table<ElectronicItem> key(code) electronicsTable = table [
    {
        "code": "APMBA132021",
        "brand": "Apple",
        "model": "Mac Book AIR M1 (13-inch 2021)",
        "price": "$1249.00",
        "qty": 32
    },
    {
        "code": "SOWH1000XM4",
        "brand": "Sony",
        "model": "WH-1000XM4",
        "price": "$349.99",
        "qty": 75
    }
];

type BookItem record {|
    readonly string code;
    string title;
    string authors;
    string price;
    int qty;
|};

table<BookItem> key(code) booksTable = table [
    {
        "code": "978-1617295959",
        "title": "Microservices Security in Action",
        "authors": "Prabath Siriwardena and Nuwan Dias",
        "price": "$50.99",
        "qty": 10
    },
    {
        "code": "978-1484220498",
        "title": "Advanced API Security",
        "authors": "Prabath Siriwardena",
        "price": "$15.39",
        "qty": 10
    }
];

type InventoryItem ElectronicItem|BookItem;

map<table<InventoryItem>> inventory = {
    electronics: electronicsTable,
    books: booksTable
};
